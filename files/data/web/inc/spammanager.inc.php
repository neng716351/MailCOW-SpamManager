<?php
/** Local admin facade over native Mailcow policies and the Rspamd controller. */
function sm_controller(string $path, ?array $body = null): array {
  $allowed = ['actions','symbols','stat','history','auth','saveactions','savesymbols'];
  if (!in_array($path, $allowed, true)) throw new InvalidArgumentException('不支援的 Rspamd 操作。');
  $c = curl_init('http://rspamd/' . $path);
  curl_setopt_array($c, [CURLOPT_UNIX_SOCKET_PATH => '/var/lib/rspamd/rspamd.sock', CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 12]);
  if ($body !== null) curl_setopt_array($c, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR), CURLOPT_HTTPHEADER => ['Content-Type: application/json']]);
  $raw = curl_exec($c); $code = curl_getinfo($c, CURLINFO_HTTP_CODE); $error = curl_error($c); curl_close($c);
  if ($raw === false || $code !== 200) throw new RuntimeException('Rspamd 未完成操作（HTTP ' . $code . '）。' . ($error ? ' 請檢查服務連線。' : ''));
  $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
  if (!is_array($data) || isset($data['error'])) throw new RuntimeException('Rspamd 回覆操作失敗。');
  return $data;
}
function sm_actions(): array {
  $out=[]; foreach (sm_controller('actions') as $v) $out[$v['action']]=$v['value']; return $out;
}
function sm_symbols(): array {
  $out=[];
  foreach (sm_controller('symbols') as $group) foreach (($group['rules'] ?? []) as $r) {
    $name=$r['symbol'];
    $out[$name]=['name'=>$name,'group'=>$group['group'],'weight'=>(float)$r['weight'],'description'=>$r['description'] ?? '', 'frequency'=>$r['frequency'] ?? 0];
  }
  ksort($out);return array_values($out);
}
function sm_maps(): array {
  global $RSPAMD_MAPS;
  $labels=['global_mime_from_blacklist.map'=>'From 寄件人黑名單','global_mime_from_whitelist.map'=>'From 寄件人白名單','global_smtp_from_blacklist.map'=>'SMTP 寄件人黑名單','global_smtp_from_whitelist.map'=>'SMTP 寄件人白名單','global_rcpt_blacklist.map'=>'收件人黑名單','global_rcpt_whitelist.map'=>'收件人白名單'];
  $out=[];
  foreach ($RSPAMD_MAPS['regex'] as $label=>$file) {
    $path='/rspamd_custom_maps/'.$file;
    if (!is_file($path)) continue;
    $content=file_get_contents($path);
    $entries=array_filter(preg_split('/\R/u',$content),fn($line)=>trim($line)!=='' && !str_starts_with(ltrim($line),'#'));
    $out[$file]=['file'=>$file,'label'=>$labels[$file] ?? $label,'content'=>$content,'hash'=>hash('sha256',$content),'count'=>count($entries),'global'=>isset($labels[$file])];
  }
  return $out;
}
function sm_policies(): array {
  global $pdo;
  $rows=$pdo->query("SELECT prefid,object,`option`,value FROM filterconf WHERE `option` IN ('whitelist_from','blacklist_from','lowspamlevel','highspamlevel') ORDER BY object,`option`,prefid")->fetchAll(PDO::FETCH_ASSOC);
  foreach($rows as &$row)$row['hash']=hash('sha256',json_encode([$row['object'],$row['option'],$row['value']]));unset($row);return $rows;
}
function sm_targets(): array {
  global $pdo;
  return $pdo->query('SELECT username AS object FROM mailbox UNION SELECT domain AS object FROM domain ORDER BY object')->fetchAll(PDO::FETCH_COLUMN);
}
function sm_rules(): array {
  return array_map(function($r){$d=rsettings('details',$r['id']);return ['id'=>$r['id'],'description'=>$d['desc'],'active'=>(bool)$d['active'],'model'=>impersonation_model($d['content']),'hash'=>hash('sha256',$d['content'])];},rsettings('get'));
}
function sm_state(): array {
  $out=['errors'=>[],'maps'=>sm_maps(),'policies'=>sm_policies(),'targets'=>sm_targets(),'rules'=>sm_rules(),'actions'=>null,'symbols'=>[],'stats'=>null];
  foreach (['actions'=>'sm_actions','symbols'=>'sm_symbols','stats'=>fn()=>sm_controller('stat')] as $key=>$fn) {
    try {$out[$key]=$fn();}catch(Throwable $e){$out['errors'][]=$e->getMessage();}
  }
  $out['scope_baselines']=[];foreach($out['targets'] as $target)$out['scope_baselines'][$target]=sm_scope_hash($target,$out['policies']);
  $out['audit']=sm_audit_entries();return $out;
}
function sm_scope_hash(string $object,array $policies): string {
  $rows=[];foreach($policies as $v)if($v['object']===$object && in_array($v['option'],['lowspamlevel','highspamlevel'],true))$rows[] = [$v['prefid'],$v['option'],$v['value']];
  return hash('sha256',json_encode($rows));
}
function sm_audit_entries(): array {
  global $redis;
  $out=[];
  foreach ($redis->lRange('SPAMMANAGER_AUDIT',0,19) as $json) {
    $v=json_decode($json,true);if(!$v)continue;
    $out[]=['time'=>$v['time'],'actor'=>$v['actor'],'operation'=>$v['operation'],'id'=>$v['id']];
  }
  return $out;
}
function sm_backup(string $op, $before, $after): string {
  global $redis;
  $id=bin2hex(random_bytes(8));
  $redis->lPush('SPAMMANAGER_AUDIT',json_encode(['id'=>$id,'time'=>date(DATE_ATOM),'actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin','operation'=>$op,'before'=>$before,'after'=>$after],JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
  $redis->lTrim('SPAMMANAGER_AUDIT',0,199);
  return $id;
}
function sm_number($v, float $min=-10000, float $max=10000): float {
  if (!is_numeric($v) || !is_finite((float)$v) || $v<$min || $v>$max) throw new InvalidArgumentException('分數格式或範圍不正確。');return (float)$v;
}
function sm_equal($a,$b): bool {return ($a===null || $b===null) ? $a===$b : abs((float)$a-(float)$b)<0.000001;}
function sm_native(callable $fn): void {
  $offset=count($_SESSION['return'] ?? []);$result=$fn();
  $messages=array_slice($_SESSION['return'] ?? [],$offset);
  foreach($messages as $v)if(in_array($v['type'],['danger','warning'],true))throw new InvalidArgumentException('原生設定未儲存：'.(is_array($v['msg'])?implode(' ',array_filter($v['msg'],'is_scalar')):$v['msg']));
  if($result===false)throw new InvalidArgumentException('沒有權限或設定未通過驗證。');
}
function sm_mutate(string $op,array $p): array {
  global $pdo;
  switch($op){
    case 'save_actions':
      $old=sm_actions();$new=[];
      foreach(['greylist','add header','reject'] as $key){
        $new[$key]=sm_number($p['values'][$key] ?? null,0,10000);
        if(!array_key_exists($key,$p['baseline'] ?? []) || !sm_equal($old[$key] ?? null,$p['baseline'][$key]))throw new RuntimeException('門檻已被其他管理者修改，請重新載入後再儲存。');
      }
      if(!($new['greylist']<$new['add header'] && $new['add header']<$new['reject']))throw new InvalidArgumentException('門檻必須符合：灰名單 < 垃圾標記 < 拒收。');
      $rewrite=$old['rewrite subject'] ?? null;
      if($rewrite!==null && !($new['add header']<$rewrite && $rewrite<$new['reject']))throw new InvalidArgumentException('既有主旨改寫門檻必須介於垃圾標記與拒收之間，請保留此順序。');
      sm_backup($op,$old,$new);
      sm_controller('saveactions',[$new['reject'],$rewrite,$new['add header'],$new['greylist']]);
      $actual=sm_actions();foreach($new as $k=>$v)if(!sm_equal($actual[$k] ?? null,$v))throw new RuntimeException('Rspamd 回讀的門檻不符，請重新整理確認。');
      return ['message'=>'全域評分門檻已儲存並由 Rspamd 回讀確認。','actions'=>$actual];
    case 'save_symbols':
      $current=array_column(sm_symbols(),null,'name');$changes=$p['changes'] ?? [];
      if(!is_array($changes) || count($changes)<1 || count($changes)>100)throw new InvalidArgumentException('一次請調整 1 至 100 項權重。');
      $before=[];$values=[];$seen=[];
      foreach($changes as $v){
        $name=(string)($v['name'] ?? '');if(!isset($current[$name]) || isset($seen[$name]))throw new InvalidArgumentException('未知或重複的評分項目。');$seen[$name]=true;
        if(!isset($v['baseline']) || !sm_equal($current[$name]['weight'],$v['baseline']))throw new RuntimeException($name.' 權重已變更，請重新載入。');
        $weight=sm_number($v['value']);
        if(sm_equal($current[$name]['weight'],$weight))continue;
        $before[$name]=$current[$name]['weight'];$values[]=['name'=>$name,'value'=>$weight];
      }
      if(!$values)return ['message'=>'權重與目前設定相同，無需重複寫入。'];
      sm_backup($op,$before,$values);sm_controller('savesymbols',$values);
      $actual=array_column(sm_symbols(),null,'name');foreach($values as $v)if(!sm_equal($actual[$v['name']]['weight'],$v['value']))throw new RuntimeException('權重回讀不符，請重新整理確認。');
      return ['message'=>'評分權重已儲存並回讀確認。'];
    case 'save_map':
      $maps=sm_maps();$file=(string)($p['file'] ?? '');if(!isset($maps[$file]))throw new InvalidArgumentException('未知的名單。');$old=$maps[$file];
      if(!hash_equals($old['hash'],(string)($p['baseline'] ?? '')))throw new RuntimeException('名單已被修改，請重新載入後合併。');
      $content=$p['content'] ?? '';if(!is_string($content) || strlen($content)>262144)throw new InvalidArgumentException('名單內容過長。');
      $lines=preg_split('/\R/u',$content);if(count($lines)>2000)throw new InvalidArgumentException('每份名單最多 2000 行。');
      foreach($lines as $i=>$line){$line=trim($line);if($line==='' || str_starts_with($line,'#'))continue;if(!is_valid_regex($line))throw new InvalidArgumentException('第 '.($i+1).' 行正規表示式格式不正確。');}
      sm_backup($op,$old,['file'=>$file,'content'=>$content]);sm_native(fn()=>rspamd_maps('edit',['map'=>[$file],'rspamd_map_data'=>$content]));
      $actual=sm_maps()[$file];if($actual['content']!==trim($content).PHP_EOL)throw new RuntimeException('名單回讀不符。');
      return ['message'=>'名單已儲存，Rspamd 會依原生動態名單機制重新載入。','map'=>$actual];
    case 'policy_add':
      $object=(string)($p['object'] ?? '');if(!in_array($object,sm_targets(),true))throw new InvalidArgumentException('請選擇既有網域或信箱。');
      $kind=$p['kind'] ?? '';if(!in_array($kind,['wl','bl'],true))throw new InvalidArgumentException('名單類型不正確。');
      $value=trim((string)($p['value'] ?? ''));if(strlen($value)>100)throw new InvalidArgumentException('寄件者條件最多 100 字元。');
      sm_backup($op,null,$p);$scope=str_contains($object,'@')?'mailbox':'domain';
      sm_native(fn()=>policy('add',$scope,[$scope==='mailbox'?'username':'domain'=>$object,'object_list'=>$kind,'object_from'=>$value]));
      return ['message'=>'個別寄件者名單已儲存。'];
    case 'policy_delete':
      $s=$pdo->prepare("SELECT * FROM filterconf WHERE prefid=? AND `option` IN ('whitelist_from','blacklist_from')");$s->execute([$p['id'] ?? 0]);$old=$s->fetch(PDO::FETCH_ASSOC);if(!$old)throw new InvalidArgumentException('名單項目不存在。');
      if(!hash_equals(hash('sha256',json_encode([$old['object'],$old['option'],$old['value']])),(string)($p['baseline'] ?? '')))throw new RuntimeException('名單已變更，請重新載入。');
      sm_backup($op,$old,null);sm_native(fn()=>policy('delete',str_contains($old['object'],'@')?'mailbox':'domain',['prefid'=>[$old['prefid']]]));return ['message'=>'個別名單項目已移除。'];
    case 'scope_score':
      $object=(string)($p['object'] ?? '');if(!in_array($object,sm_targets(),true))throw new InvalidArgumentException('請選擇既有網域或信箱。');
      $before=array_values(array_filter(sm_policies(),fn($v)=>$v['object']===$object && in_array($v['option'],['lowspamlevel','highspamlevel'])));
      if(!hash_equals(sm_scope_hash($object,sm_policies()),(string)($p['baseline'] ?? '')))throw new RuntimeException('個別門檻已被修改，請重新讀取設定。');
      $tag=sm_number($p['tag'] ?? null,1,9999);$reject=sm_number($p['reject'] ?? null,1,10000);if($tag>=$reject)throw new InvalidArgumentException('垃圾標記門檻必須小於拒收門檻。');
      sm_backup($op,$before,$p);$pdo->beginTransaction();try{
        $q=$pdo->prepare("DELETE FROM filterconf WHERE object=? AND `option` IN ('lowspamlevel','highspamlevel')");$q->execute([$object]);
        if(empty($p['reset'])){$q=$pdo->prepare('INSERT INTO filterconf (object,`option`,value) VALUES (?,?,?)');$q->execute([$object,'lowspamlevel',$tag]);$q->execute([$object,'highspamlevel',$reject]);}
        $pdo->commit();
      }catch(Throwable $e){$pdo->rollBack();throw $e;}
      return ['message'=>!empty($p['reset'])?'已恢復繼承全域評分門檻。':'個別門檻已儲存；此範圍的灰名單門檻為垃圾標記門檻減 1。'];
    case 'impersonation_save':
    case 'impersonation_delete':
      $id=(string)($p['id'] ?? '');$old=$id!==''?rsettings('details',$id):null;
      if($id!=='' && (!$old || !impersonation_model($old['content'])))throw new InvalidArgumentException('只能在此管理防冒名表單建立或辨識的規則。');
      if($old && isset($p['baseline']) && !hash_equals(hash('sha256',$old['content']),(string)$p['baseline']))throw new RuntimeException('規則已變更，請重新整理。');
      if($op==='impersonation_delete'){
        if(!$old)throw new InvalidArgumentException('請指定規則。');sm_backup($op,$old,null);sm_native(fn()=>rsettings('delete',['id'=>[$id]]));return ['message'=>'防冒名規則已移除。','rules'=>sm_rules()];
      }
      $model=impersonation_validate($p['impersonation_name'] ?? '',$p['impersonation_emails'] ?? []);
      if(!$old)foreach(sm_rules() as $existing)if($existing['model'] && $existing['model']['name']===$model['name'])throw new InvalidArgumentException('相同顯示名稱已有規則，請選擇該規則編輯。');
      sm_backup($op,$old,$model);$input=['impersonation_name'=>$model['name'],'impersonation_emails'=>$model['emails'],'active'=>!empty($p['active'])?1:0];
      if($id!=='')$input['id']=[$id];sm_native(fn()=>rsettings($id!==''?'edit':'add',$input));$savedId=$id!==''?$id:$pdo->lastInsertId();return ['message'=>'防冒名規則已儲存。','rules'=>sm_rules(),'id'=>$savedId];
    default:throw new InvalidArgumentException('未知的操作。');
  }
}

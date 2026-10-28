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
function sm_rejected(): array {
  // Native quarantine stores a copy of rejected mail whose recipient is a local
  // mailbox (SMTP-stage and some blacklisted rejects are not captured). Reuse the
  // native getter and surface only reject items for release.
  $items = quarantine('get');
  if (!is_array($items)) return [];
  $out = [];
  foreach ($items as $r) {
    if (($r['action'] ?? '') !== 'reject') continue;
    $out[] = [
      'id' => (int)($r['id'] ?? 0),
      'qid' => (string)($r['qid'] ?? ''),
      'created' => isset($r['created']) ? (int)$r['created'] : null,
      'sender' => (string)($r['sender'] ?? ''),
      'rcpt' => (string)($r['rcpt'] ?? ''),
      'subject' => (string)($r['subject'] ?? ''),
      'score' => isset($r['score']) ? (float)$r['score'] : 0.0,
      'virus' => !empty($r['virus_flag']),
    ];
  }
  usort($out, fn($a, $b) => ($b['created'] ?? 0) <=> ($a['created'] ?? 0));
  return $out;
}
function sm_outbound(): array {
  // Outbound (authenticated local sender) mail that was rejected and held for review.
  global $pdo;
  $rows = $pdo->query("SELECT `id`,`qid`,UNIX_TIMESTAMP(`created`) AS `created`,`sender`,`rcpt`,`subject`,`score`,`virus`,`user` FROM `outbound_hold` WHERE `released`=0 ORDER BY `created` DESC LIMIT 500")->fetchAll(PDO::FETCH_ASSOC);
  return array_map(fn($r) => [
    'id' => (int)$r['id'], 'created' => (int)$r['created'], 'sender' => (string)$r['sender'],
    'rcpt' => (string)$r['rcpt'], 'subject' => (string)$r['subject'], 'score' => (float)$r['score'],
    'virus' => (bool)$r['virus'], 'user' => (string)$r['user'],
  ], $rows);
}
function sm_outbound_notify(): string {
  // Admin recipient(s) notified when an outbound message is held. Stored in Redis so
  // both the web UI and the rspamd pipe_outbound.php endpoint read the same value.
  global $redis;
  try { $v = $redis->Get('OUTBOUND_HOLD_NOTIFY'); } catch (Throwable $e) { $v = false; }
  return ($v !== false && $v !== '') ? (string)$v : '';
}
function sm_rejected_notify(): string {
  // Admin recipient(s) notified when INBOUND mail is rejected. Empty = notifications off.
  global $redis;
  try { $v = $redis->Get('REJECTED_HOLD_NOTIFY'); } catch (Throwable $e) { $v = false; }
  return ($v !== false && $v !== '') ? (string)$v : '';
}
function sm_parse_addresses($raw): array {
  $parts = preg_split('/[\s,;]+/u', (string)$raw, -1, PREG_SPLIT_NO_EMPTY);
  $out = [];
  foreach ($parts as $p) {
    $p = trim($p);
    if (!filter_var($p, FILTER_VALIDATE_EMAIL)) throw new InvalidArgumentException('收件人格式不正確：' . $p);
    if (!in_array($p, $out, true)) $out[] = $p;
  }
  if (!$out) throw new InvalidArgumentException('請至少輸入一個通知收件人。');
  if (count($out) > 5) throw new InvalidArgumentException('通知收件人最多 5 個。');
  return $out;
}
function sm_reinject(string $sender, string $rcpt, string $msg): void {
  // Deliver a stored raw message to the (external) recipient via Postfix port 590 — the
  // milter-bypassing reinjection listener, the same path native quarantine release uses.
  // This sends mail externally and bypasses the rejection, so callers must be admin and audited.
  $host = !empty(gethostbynamel('postfix-mailcow')) ? 'postfix-mailcow' : 'postfix';
  $fp = @fsockopen($host, 590, $errno, $errstr, 5);
  if (!$fp) throw new RuntimeException('無法連線郵件投遞服務（590）：' . $errstr);
  stream_set_timeout($fp, 20);
  $data = preg_replace('~^\.~m', '..', $msg); // dot-stuffing per RFC5321 4.5.2
  $talk = [
    ['220', "HELO outbound-release\r\n"],
    ['250', 'MAIL FROM:<' . $sender . ">\r\n"],
    ['250', 'RCPT TO:<' . $rcpt . ">\r\n"],
    ['250', "DATA\r\n"],
    ['354', $data . "\r\n.\r\n"],
    ['250', "QUIT\r\n"],
  ];
  foreach ($talk as $step) {
    $resp = fgets($fp, 1024);
    if (strpos((string)$resp, $step[0]) !== 0) { fclose($fp); throw new RuntimeException('投遞未被接受（預期 ' . $step[0] . '）：' . trim((string)$resp)); }
    fwrite($fp, $step[1]);
  }
  fclose($fp);
}
function sm_customizations(): array {
  // Live check that this deployment's local customizations are still in place. update.sh
  // runs `git merge -X theirs`, so a tracked file we modified can be reverted whenever
  // upstream touches the same lines. The checklist itself is deployment-specific and lives
  // in spammanager.customizations.json (see the .example file) so this code stays generic.
  $manifest = __DIR__ . '/spammanager.customizations.json';
  if (!is_readable($manifest)) return [['name'=>'自訂設定清單','status'=>'unknown','detail'=>'找不到 spammanager.customizations.json，請參考 .example 建立。']];
  $cfg = json_decode((string)file_get_contents($manifest), true);
  if (!is_array($cfg)) return [['name'=>'自訂設定清單','status'=>'unknown','detail'=>'spammanager.customizations.json 格式不正確。']];
  $out = [];
  foreach (($cfg['checks'] ?? []) as $c) {
    $name = (string)($c['name'] ?? '?'); $path = (string)($c['path'] ?? '');
    if ($path === '' || !is_readable($path)) { $out[] = ['name'=>$name,'status'=>'unknown','detail'=>'無法讀取（請確認掛載）：'.$path]; continue; }
    $text = (string)file_get_contents($path);
    $bad = [];
    foreach (($c['must'] ?? []) as $m) if (!str_contains($text, (string)$m)) $bad[] = '缺少 '.$m;
    foreach (($c['must_not'] ?? []) as $m) if (str_contains($text, (string)$m)) $bad[] = '殘留上游內容 '.$m;
    $out[] = ['name'=>$name,'status'=>$bad?'missing':'ok','detail'=>implode('；',$bad)];
  }
  $files = $cfg['files'] ?? [];
  if ($files) {
    $gone = array_values(array_filter($files, fn($p) => !is_readable($p)));
    $out[] = $gone
      ? ['name'=>'自訂程式檔（未追蹤）','status'=>'missing','detail'=>'遺失：'.implode('、', array_map('basename', $gone))]
      : ['name'=>'自訂程式檔（未追蹤）','status'=>'ok','detail'=>count($files).' 個檔案齊全'];
  }
  return $out;
}
function sm_update_status(): array {
  // Status of the host-side update agent. The web layer only reads what the agent wrote;
  // it never runs the update itself and never sees the update passphrase hash.
  $dir = '/updater';
  $out = ['available' => is_dir($dir) && is_writable($dir), 'state' => 'idle', 'message' => '', 'updated' => null, 'log' => '', 'pending' => false];
  if (!$out['available']) { $out['message'] = '尚未啟用網頁更新（請在主機執行 setup-updater-agent.sh）。'; return $out; }
  $out['pending'] = is_file($dir . '/request.json');
  if (is_readable($dir . '/status.json')) {
    $s = json_decode((string)file_get_contents($dir . '/status.json'), true);
    if (is_array($s)) {
      $out['state'] = (string)($s['state'] ?? 'idle');
      $out['message'] = (string)($s['message'] ?? '');
      $out['updated'] = isset($s['updated']) ? (int)$s['updated'] : null;
    }
  }
  if (is_readable($dir . '/update.log')) {
    $raw = (string)file_get_contents($dir . '/update.log');
    $lines = preg_split('/\R/u', rtrim($raw));
    $out['log'] = implode("\n", array_slice($lines, -40));
  }
  return $out;
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
    case 'release':
      $id=$p['id'] ?? null;
      if(!(is_int($id) || (is_string($id) && ctype_digit($id))))throw new InvalidArgumentException('請指定要放行的郵件。');
      $id=(int)$id;
      $s=$pdo->prepare("SELECT `rcpt`,`action`,`sender`,`subject` FROM `quarantine` WHERE `id`=:id");$s->execute([':id'=>$id]);$row=$s->fetch(PDO::FETCH_ASSOC);
      if(!$row)throw new InvalidArgumentException('找不到該郵件，可能已放行、刪除或過期。');
      if(($row['action'] ?? '')!=='reject')throw new InvalidArgumentException('此功能只放行「拒收」的郵件。');
      sm_backup($op,['id'=>$id,'rcpt'=>$row['rcpt'],'sender'=>$row['sender'],'subject'=>$row['subject']],null);
      sm_native(fn()=>quarantine('edit',['action'=>'release','id'=>$id]));
      return ['message'=>'已放行並投遞至 '.$row['rcpt'].'。此副本仍保留於隔離區，可於原生隔離區刪除。'];
    case 'outbound_release':
      $id=$p['id'] ?? null;
      if(!(is_int($id) || (is_string($id) && ctype_digit($id))))throw new InvalidArgumentException('請指定要放行的郵件。');
      $id=(int)$id;
      $s=$pdo->prepare("SELECT `sender`,`rcpt`,`msg`,`virus`,`released` FROM `outbound_hold` WHERE `id`=:id");$s->execute([':id'=>$id]);$row=$s->fetch(PDO::FETCH_ASSOC);
      if(!$row)throw new InvalidArgumentException('找不到該郵件，可能已放行、刪除或過期。');
      if((int)$row['released']===1)throw new InvalidArgumentException('此郵件已放行過。');
      if((int)$row['virus']===1 && empty($p['confirm_virus']))throw new InvalidArgumentException('這封外寄信命中病毒掃描，放行會把它寄給外部收件人。請再次確認後放行。');
      if(empty($row['rcpt']))throw new InvalidArgumentException('缺少外部收件人，無法放行。');
      sm_backup($op,['id'=>$id,'sender'=>$row['sender'],'rcpt'=>$row['rcpt'],'virus'=>(int)$row['virus']],null);
      sm_reinject((string)$row['sender'],(string)$row['rcpt'],(string)$row['msg']);
      $u=$pdo->prepare("UPDATE `outbound_hold` SET `released`=1,`decided_by`=:who WHERE `id`=:id");$u->execute([':who'=>$_SESSION['mailcow_cc_username'] ?? 'admin',':id'=>$id]);
      return ['message'=>'已放行並寄給外部收件人 '.$row['rcpt'].'。'];
    case 'outbound_delete':
      $id=$p['id'] ?? null;
      if(!(is_int($id) || (is_string($id) && ctype_digit($id))))throw new InvalidArgumentException('請指定要刪除的郵件。');
      $id=(int)$id;
      $s=$pdo->prepare("SELECT `sender`,`rcpt`,`subject` FROM `outbound_hold` WHERE `id`=:id");$s->execute([':id'=>$id]);$row=$s->fetch(PDO::FETCH_ASSOC);
      if(!$row)throw new InvalidArgumentException('找不到該郵件，可能已處理。');
      sm_backup($op,['id'=>$id,'sender'=>$row['sender'],'rcpt'=>$row['rcpt'],'subject'=>$row['subject']],null);
      $pdo->prepare("DELETE FROM `outbound_hold` WHERE `id`=:id")->execute([':id'=>$id]);
      return ['message'=>'已刪除該被攔截的外寄郵件，不會寄出。'];
    case 'update_request':
      // Hand the request to the privileged host agent. The passphrase is NOT checked here
      // on purpose: it is verified by the root agent, so a compromised web layer writing
      // this file directly still cannot trigger an update without knowing the passphrase.
      $dir='/updater';
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁更新，請先在主機執行 setup-updater-agent.sh。');
      $pass=(string)($p['passphrase'] ?? '');
      if($pass==='')throw new InvalidArgumentException('請輸入更新密碼。');
      if(strlen($pass)>256)throw new InvalidArgumentException('更新密碼過長。');
      if(is_file($dir.'/request.json'))throw new RuntimeException('已有一筆更新請求待處理，請稍候。');
      $status=sm_update_status();
      if(($status['state'] ?? '')==='running')throw new RuntimeException('更新正在進行中。');
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin']);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin','passphrase'=>$pass],JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.request.tmp';
      if(file_put_contents($tmp,$payload)===false)throw new RuntimeException('無法寫入更新請求。');
      chmod($tmp,0600);
      if(!rename($tmp,$dir.'/request.json')){@unlink($tmp);throw new RuntimeException('無法送出更新請求。');}
      return ['message'=>'已送出更新請求。主機會驗證更新密碼後開始更新；更新期間網頁會短暫中斷，完成後此頁會顯示結果。'];
    case 'outbound_notify_save':
    case 'rejected_notify_save':
      global $redis;
      $outbound=($op==='outbound_notify_save');
      $key=$outbound?'OUTBOUND_HOLD_NOTIFY':'REJECTED_HOLD_NOTIFY';
      $old=$outbound?sm_outbound_notify():sm_rejected_notify();
      $raw=trim((string)($p['value'] ?? ''));
      // Inbound notifications are optional: an empty list turns them off.
      if(!$outbound && $raw===''){$new='';}
      else{$new=implode(',',sm_parse_addresses($raw));}
      sm_backup($op,$old,$new);
      try{$redis->Set($key,$new);}catch(Throwable $e){throw new RuntimeException('無法儲存設定（Redis）。');}
      $readback=$outbound?sm_outbound_notify():sm_rejected_notify();
      if($readback!==$new)throw new RuntimeException('設定回讀不符，請重試。');
      return ['message'=>$new===''?'已關閉此類通知。':'通知收件人已更新為：'.$new,'notify'=>$new];
    default:throw new InvalidArgumentException('未知的操作。');
  }
}

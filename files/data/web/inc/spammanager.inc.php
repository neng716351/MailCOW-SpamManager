<?php
// Components the WEB UI may restore. Mail data (vmail/crypt) is deliberately absent:
// it can overwrite every mailbox, so it stays a host-only operation.
const SM_RESTORE_WEB_COMPONENTS = ['mysql', 'redis', 'rspamd', 'postfix'];
// SMB dialects we let the page choose from; the host script enforces the same list.
const SM_NAS_SMB_VERSIONS = ['3.1.1', '3.0', '2.1', '2.0', '1.0'];
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
// Map kinds mirror the $RSPAMD_MAPS keys: 'regex' lines are rspamd regular
// expressions, 'ip' lines are addresses or CIDR ranges, 'asn' lines are
// "<asn> [score] [#comment]". Each kind needs its own validator, so the kind
// travels with the map to both the page and save_map().
const SM_MAP_KIND_HINT = [
  'regex' => '不是合法的正規表示式',
  'ip' => '不是合法的 IP 位址或 CIDR 網段',
  'asn' => '不是合法的 ASN 條目（格式：ASN，或 ASN 加一個分數倍數，可再加 # 說明）',
  'url' => '不是合法的網域（請填 example.com 這種純網域，不要加 http:// 或路徑）',
];
function sm_valid_ip_entry(string $line): bool {
  if (!str_contains($line, '/')) return (bool)filter_var($line, FILTER_VALIDATE_IP);
  [$addr, $len] = explode('/', $line, 2);
  if (!ctype_digit($len) || !filter_var($addr, FILTER_VALIDATE_IP)) return false;
  return (int)$len <= (str_contains($addr, ':') ? 128 : 32);
}
function sm_valid_asn_entry(string $line): bool {
  // A trailing "# ..." comment is how the shipped bad_asn.map annotates providers.
  $parts = preg_split('/\s+/u', trim(preg_replace('/\s*#.*$/u', '', $line)), -1, PREG_SPLIT_NO_EMPTY);
  if (!$parts || count($parts) > 2) return false;
  $asn = preg_replace('/^AS/i', '', $parts[0]);
  if (!ctype_digit($asn) || (int)$asn < 1 || (int)$asn > 4294967295) return false;
  return count($parts) === 1 || is_numeric($parts[1]);
}
function sm_valid_domain_entry(string $line): bool {
  // multimap's url/tld filter hands us a registrable domain, so the map holds bare
  // domains -- not regexes, not URLs. Reject anything with a scheme, path or wildcard
  // so a pasted link cannot silently become a rule that never matches.
  $line = trim(preg_replace('/\s*#.*$/u', '', $line));
  if ($line === '' || strlen($line) > 253) return false;
  if (preg_match('~[/:\s*?]~u', $line)) return false;
  return (bool)preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $line);
}
function sm_valid_map_entry(string $kind, string $line): bool {
  if ($kind === 'ip') return sm_valid_ip_entry($line);
  if ($kind === 'asn') return sm_valid_asn_entry($line);
  if ($kind === 'url') return sm_valid_domain_entry($line);
  return is_valid_regex($line);
}
function sm_maps(): array {
  global $RSPAMD_MAPS;
  $labels=['global_mime_from_blacklist.map'=>'From 寄件人黑名單','global_mime_from_whitelist.map'=>'From 寄件人白名單','global_smtp_from_blacklist.map'=>'SMTP 寄件人黑名單','global_smtp_from_whitelist.map'=>'SMTP 寄件人白名單','global_rcpt_blacklist.map'=>'收件人黑名單','global_rcpt_whitelist.map'=>'收件人白名單','global_helo_whitelist.map'=>'寄件主機 HELO 白名單','global_helo_blacklist.map'=>'寄件主機 HELO 黑名單','global_hostname_whitelist.map'=>'寄件主機反解名稱白名單','global_hostname_blacklist.map'=>'寄件主機反解名稱黑名單','ip_wl.map'=>'來源 IP／網段白名單','global_ip_blacklist.map'=>'來源 IP／網段黑名單','bad_asn.map'=>'來源 ASN 黑名單','global_url_blacklist.map'=>'郵件內連結網域黑名單'];
  $out=[];
  foreach ($RSPAMD_MAPS as $kind=>$files) {
    if (!is_array($files) || !isset(SM_MAP_KIND_HINT[$kind])) continue;
    foreach ($files as $label=>$file) {
      $path='/rspamd_custom_maps/'.$file;
      if (!is_file($path)) continue;
      $content=file_get_contents($path);
      $entries=array_filter(preg_split('/\R/u',$content),fn($line)=>trim($line)!=='' && !str_starts_with(ltrim($line),'#'));
      $out[$file]=['file'=>$file,'kind'=>$kind,'label'=>$labels[$file] ?? $label,'content'=>$content,'hash'=>hash('sha256',$content),'count'=>count($entries),'global'=>isset($labels[$file])];
    }
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
  // Native quarantine stores a copy of mail whose recipient is a local mailbox
  // (SMTP-stage and some blacklisted rejects are not captured). Reuse the native
  // getter and return every held item with its action: since the quarantine
  // selector was widened on 2026-10-28 the table also holds 'add header' and
  // 'rewrite subject' mail, and the page filters by action. Only 'reject' items
  // can be released, which the 'release' operation re-checks server-side.
  $items = quarantine('get');
  if (!is_array($items)) return [];
  $out = [];
  foreach ($items as $r) {
    $out[] = [
      'action' => (string)($r['action'] ?? ''),
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
  // Since 2026-11-13 the selector keeps every inbound message, so this list grows with
  // mail volume rather than with spam volume. Cap what the page loads; older copies are
  // purged by Q_MAX_AGE anyway, and the admin filters/searches within the newest slice.
  return array_slice($out, 0, 2000);
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
  // in spammanager.customizations.php (see the .example file) so this code stays generic.
  // PHP, not JSON: Mailcow serves /inc/ to anyone, and a .json there is downloadable as-is,
  // while a .php is executed and returns nothing. The file still holds plain JSON.
  $manifest = __DIR__ . '/spammanager.customizations.php';
  $legacy = __DIR__ . '/spammanager.customizations.json';
  $notice = [];
  if (is_readable($manifest)) {
    $cfg = include $manifest;
  } elseif (is_readable($legacy)) {
    $cfg = json_decode((string)file_get_contents($legacy), true);
    $notice[] = ['name'=>'自訂設定清單','status'=>'missing','detail'=>'spammanager.customizations.json 可從外部直接下載，請改用 spammanager.customizations.php。'];
  } else {
    return [['name'=>'自訂設定清單','status'=>'unknown','detail'=>'找不到 spammanager.customizations.php，請參考 .example 建立。']];
  }
  if (!is_array($cfg)) return [['name'=>'自訂設定清單','status'=>'unknown','detail'=>'spammanager.customizations.php 格式不正確。']];
  $out = $notice;
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
// The five numbered stages mailcow-oneclick-update.sh prints as "==> 步驟 N/5：...".
const SM_UPDATE_STEPS = [
  1 => '備份自訂設定', 2 => '更新前檢查', 3 => '官方更新（update.sh）',
  4 => '重新套用自訂設定', 5 => '驗證',
];
/**
 * Turn the raw update log into what the page needs: the whole log (minus per-layer
 * docker pull progress, folded into one summary line per image), the step each stage
 * reached, every problem line, and the before/after version.
 */
function sm_parse_update_log(string $raw): array {
  // Colours AND cursor movement: docker pull redraws its progress with ESC[1A/ESC[2K.
  $raw = preg_replace('/\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-Za-z]/', '', $raw);
  $raw = preg_replace('/^\[[0-9;]*m/m', '', $raw);
  $lines = preg_split('/\R/u', rtrim(str_replace("\r", "\n", $raw)));
  $keep = []; $blank = 0; $layers = 0; $gitstat = 0; $okcount = 0; $in_summary = false;
  $steps = []; foreach (SM_UPDATE_STEPS as $n => $title) $steps[$n] = ['n' => $n, 'title' => $title, 'state' => 'pending', 'detail' => ''];
  $current = 0; $problems = []; $before = ''; $after = ''; $result = ''; $started = '';
  $flush_layers = function () use (&$keep, &$layers, &$gitstat, &$okcount) {
    if ($layers) { $keep[] = "    （下載容器映像：{$layers} 行逐層進度已摺疊）"; $layers = 0; }
    if ($gitstat) { $keep[] = "    （git 檔案變更清單：{$gitstat} 個檔案，已摺疊）"; $gitstat = 0; }
    if ($okcount) { $keep[] = "    （功能測試：{$okcount} 項檢查通過，已摺疊）"; $okcount = 0; }
  };
  foreach ($lines as $line) {
    $plain = rtrim($line);
    // docker pull progress: "<12 hex>: Pulling fs layer|Waiting|Download complete|..."
    if (preg_match('/^\s*[0-9a-f]{12}: (Pulling fs layer|Waiting|Downloading|Verifying Checksum|Download complete|Extracting|Pull complete|Already exists)/', $plain)) { $layers++; continue; }
    // git merge diffstat: " path/to/file | 12 +-" (or "Bin 0 -> 123 bytes")
    if (preg_match('/^ \S.*\|\s+(\d+ ?[+-]*|Bin .*)$/', $plain)
        || preg_match('/^ (create|delete) mode \d+ |^ rename .* \(\d+%\)$|^ mode change \d+ => \d+ /', $plain)) { $gitstat++; continue; }
    // Test suite: individual passing assertions. Group results (... PASS / FAIL) stay.
    if (preg_match('/^ok: /', $plain)) { $okcount++; continue; }
    $flush_layers();
    if ($plain === '') { if (++$blank > 1) continue; $keep[] = ''; continue; }
    $blank = 0;
    // A failing git command dumps its usage text; our output never indents past 4 spaces.
    if (preg_match('/^\s{6,}\S/', $plain)) continue;
    if (preg_match('/^\s{2,}-{1,2}[A-Za-z\[]/', $plain)) continue;
    $keep[] = $plain;
    if (preg_match('/^==> Mailcow 一鍵更新 — (\S+)/u', $plain, $m)) $started = $m[1];
    if (preg_match('/^==> 步驟 (\d)\/5/u', $plain, $m)) {
      $n = (int)$m[1];
      for ($i = 1; $i < $n; $i++) if ($steps[$i]['state'] === 'pending' || $steps[$i]['state'] === 'running') $steps[$i]['state'] = 'done';
      if (isset($steps[$n])) $steps[$n]['state'] = 'running';
      $current = $n;
    }
    if (preg_match('/^\s*目前版本：(.+)$/u', $plain, $m)) $before = trim($m[1]);
    if (preg_match('/^\s*更新後版本：(.+)$/u', $plain, $m)) $after = trim($m[1]);
    if (preg_match('/^==> 完成/u', $plain)) $in_summary = true;
    if (preg_match('/^\s*!!\s*(.+)$/u', $plain, $m)) {
      $msg = trim($m[1]);
      // The closing lines restate earlier problems; list them once, colour no step.
      // "共 N 項問題" is the tally line, not a problem of its own.
      if (!preg_match('/^共 \d+ 項問題/u', $msg) && !in_array($msg, $problems, true)) $problems[] = $msg;
      if (!$in_summary && $current && isset($steps[$current])) {
        $steps[$current]['state'] = 'warn';
        if ($steps[$current]['detail'] === '') $steps[$current]['detail'] = $msg;
      }
    }
    if (preg_match('/NEEDS-MANUAL|MISSING/', $plain) && $current === 4 && preg_match('/^\s{2}\S/', $plain)) {
      $steps[4]['state'] = 'warn'; $steps[4]['detail'] = '有項目需要人工處理';
    }
    if (preg_match('/^\s*未發現問題/u', $plain)) $result = 'ok';
    if (preg_match('/共 (\d+) 項問題/u', $plain)) $result = 'problems';
  }
  $flush_layers();
  if ($result !== '') {
    foreach ($steps as &$st) if ($st['state'] === 'running' || $st['state'] === 'pending') $st['state'] = $st['n'] <= max($current, 1) ? 'done' : 'skipped';
    unset($st);
  }
  if ($before !== '' && $after !== '') $steps[3]['detail'] = $before === $after ? "版本未變（{$before}）" : "{$before} → {$after}";
  // Cap what we send; the full file stays on the host for anything longer.
  $total = count($keep);
  return [
    'log' => implode("\n", array_slice($keep, -1500)),
    'log_truncated' => max(0, $total - 1500),
    'steps' => array_values($steps), 'current_step' => $current, 'problems' => $problems,
    'version_before' => $before, 'version_after' => $after, 'result' => $result, 'run_id' => $started,
  ];
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
    $out = array_merge($out, sm_parse_update_log((string)file_get_contents($dir . '/update.log')));
  }
  // Result of the last "重新驗證" (mailcow-verify.sh), kept apart from the update record.
  $out['verify'] = null;
  if (is_readable($dir . '/verify-status.json')) {
    $v = json_decode((string)file_get_contents($dir . '/verify-status.json'), true);
    if (is_array($v)) {
      $v['log'] = is_readable($dir . '/verify.log') ? (string)file_get_contents($dir . '/verify.log', false, null, 0, 200000) : '';
      $out['verify'] = $v;
    }
  }
  return $out;
}
function sm_backup_notify(): string {
  // Who gets told when a backup fails. Empty = no mail is sent (the backup still runs).
  global $redis;
  try { $v = $redis->Get('BACKUP_NOTIFY'); } catch (Throwable $e) { $v = false; }
  return ($v === false || $v === null) ? '' : (string)$v;
}

function sm_nas_backup_status(): array {
  // Status of the host-side NAS backup. The web layer only reads what the agent and the
  // backup script wrote; it never mounts the share and never sees the SMB password.
  $dir = '/updater';
  $out = [
    'available'  => is_dir($dir) && is_writable($dir),
    'configured' => false,
    'state'      => 'idle',
    'message'    => '',
    'updated'    => null,
    'target'     => '',
    'retention'  => null,
    'schedule'   => '',
    'encrypted'  => null,
    'last_success' => null,
    'last_name'  => '',
    'last_size'  => '',
    'backups'    => [],
    'log'        => '',
    'pending'    => false,
    'notify'     => sm_backup_notify(),
  ];
  if (!$out['available']) {
    $out['message'] = '尚未啟用網頁備份（請在主機執行 setup-nas-backup.sh）。';
    return $out;
  }
  $out['pending'] = is_file($dir . '/backup-request.json');

  // Target description, written by the setup script. Its presence is what tells us the
  // NAS has been configured at all, because /etc is not readable from here.
  if (is_readable($dir . '/backup-target.json')) {
    $t = json_decode((string)file_get_contents($dir . '/backup-target.json'), true);
    if (is_array($t)) {
      $out['configured'] = true;
      $out['target']     = (string)($t['target'] ?? '');
      $out['retention']  = isset($t['retention']) ? (int)$t['retention'] : null;
      $out['schedule']   = (string)($t['schedule'] ?? '');
      if (isset($t['encrypted'])) $out['encrypted'] = (bool)$t['encrypted'];
    }
  }
  if (!$out['configured']) {
    $out['message'] = is_file($dir . '/nas-webconfig.json')
      ? '尚未設定 NAS。請先在上方「NAS 連線設定」填入連線資訊並測試成功。'
      : '尚未設定 NAS。請在主機執行 helper-scripts/setup-nas-backup.sh。';
  }

  if (is_readable($dir . '/backup-status.json')) {
    $st = json_decode((string)file_get_contents($dir . '/backup-status.json'), true);
    if (is_array($st)) {
      $out['state']   = (string)($st['state'] ?? 'idle');
      $out['message'] = (string)($st['message'] ?? $out['message']);
      $out['updated'] = isset($st['updated']) ? (int)$st['updated'] : null;
      foreach (['target', 'last_name', 'last_size'] as $k) {
        if (!empty($st[$k])) $out[$k] = (string)$st[$k];
      }
      if (isset($st['retention'])) $out['retention'] = (int)$st['retention'];
      if (isset($st['encrypted'])) $out['encrypted'] = (bool)$st['encrypted'];
      if (isset($st['last_success'])) $out['last_success'] = (int)$st['last_success'];
      if (isset($st['backups']) && is_array($st['backups'])) {
        $out['backups'] = array_slice(array_values(array_filter($st['backups'], 'is_array')), 0, 20);
      }
    }
  }

  if (is_readable($dir . '/backup.log')) {
    $raw = preg_replace('/\x1b?\[[0-9;]*m/', '', (string)file_get_contents($dir . '/backup.log'));
    $lines = preg_split('/\R/u', rtrim((string)$raw));
    $out['log'] = implode("\n", array_slice($lines, -60));
  }
  return $out;
}

function sm_nas_restore_status(): array {
  // Status of the host-side restore. Only settings-class components can be restored from
  // here; vmail and crypt are refused by both the agent and the restore script.
  $dir = '/updater';
  $out = [
    'available'  => is_dir($dir) && is_writable($dir),
    'state'      => 'idle',
    'message'    => '',
    'updated'    => null,
    'backup'     => '',
    'components' => '',
    'snapshot'   => '',
    'log'        => '',
    'pending'    => false,
    'allowed'    => SM_RESTORE_WEB_COMPONENTS,
  ];
  if (!$out['available']) { $out['message'] = '尚未啟用網頁還原。'; return $out; }
  $out['pending'] = is_file($dir . '/restore-request.json');
  if (is_readable($dir . '/restore-status.json')) {
    $st = json_decode((string)file_get_contents($dir . '/restore-status.json'), true);
    if (is_array($st)) {
      foreach (['state','message','backup','components','snapshot'] as $k) {
        if (isset($st[$k])) $out[$k] = (string)$st[$k];
      }
      if (isset($st['updated'])) $out['updated'] = (int)$st['updated'];
    }
  }
  if (is_readable($dir . '/restore.log')) {
    $raw = preg_replace('/\x1b?\[[0-9;]*m/', '', (string)file_get_contents($dir . '/restore.log'));
    $out['log'] = implode("\n", array_slice(preg_split('/\R/u', rtrim((string)$raw)), -60));
  }
  return $out;
}

function sm_geo_status(): array {
  // Login-region allowlist. Written by the root agent (mailcow-geo-agent.py); the web
  // layer only reads it and drops change requests -- it never touches the firewall.
  $dir = '/updater';
  $out = ['available' => is_dir($dir) && is_writable($dir), 'configured' => false, 'state' => 'idle',
          'message' => '', 'pending' => is_file($dir . '/geo-request.json')];
  if (!$out['available']) { $out['message'] = '尚未啟用網頁主機功能。'; return $out; }
  if (!is_readable($dir . '/geo-status.json')) {
    $out['message'] = '尚未安裝登入地區限制，請在主機執行 sudo ./helper-scripts/setup-geo-allowlist.sh';
    return $out;
  }
  $st = json_decode((string)file_get_contents($dir . '/geo-status.json'), true);
  if (!is_array($st)) { $out['message'] = '狀態檔無法讀取。'; return $out; }
  $out['configured'] = true;
  foreach (['state','message','updated','policy','ports','open_ports','available_countries','active',
            'data_fetched','effective','set_v4','set_v6','counters','blocked_recent','blocked_by_country','applied'] as $k) {
    if (array_key_exists($k, $st)) $out[$k] = $st[$k];
  }
  return $out;
}
function sm_host_update_status(): array {
  // Status of host OS maintenance, written by the host-side script and agent. The web
  // layer only reads it; "check" is not web-triggerable (a daily timer does it) so no
  // root apt operation is reachable from here.
  $dir = '/updater';
  $out = [
    'available'  => is_dir($dir) && is_writable($dir),
    'configured' => false,
    'state'      => 'idle',
    'message'    => '',
    'updated'    => null,
    'checked'    => null,
    'count'      => null,
    'security'   => null,
    'deferred'   => [],
    'reboot_required' => false,
    'reboot_pkgs'     => '',
    'kernel_running'  => '',
    'kernel_installed'=> '',
    'log'        => '',
    'pending'    => false,
  ];
  if (!$out['available']) { $out['message'] = '尚未啟用網頁主機更新。'; return $out; }
  $out['pending'] = is_file($dir . '/host-request.json');

  if (is_readable($dir . '/host-status.json')) {
    $st = json_decode((string)file_get_contents($dir . '/host-status.json'), true);
    if (is_array($st)) {
      $out['configured'] = true;
      $out['state']   = (string)($st['state'] ?? 'idle');
      $out['message'] = (string)($st['message'] ?? '');
      foreach (['updated','checked'] as $k) {
        if (isset($st[$k])) $out[$k] = (int)$st[$k];
      }
      if (isset($st['available'])) $out['count']    = (int)$st['available'];
      if (isset($st['security']))  $out['security'] = (int)$st['security'];
      if (isset($st['deferred']) && is_array($st['deferred'])) {
        $out['deferred'] = array_values(array_filter(array_map('strval', $st['deferred'])));
      }
      $out['reboot_required']  = !empty($st['reboot_required']);
      $out['reboot_pkgs']      = (string)($st['reboot_pkgs'] ?? '');
      $out['kernel_running']   = (string)($st['kernel_running'] ?? '');
      $out['kernel_installed'] = (string)($st['kernel_installed'] ?? '');
    }
  }
  if (!$out['configured']) {
    $out['message'] = '尚未設定主機更新。請在主機執行 helper-scripts/setup-host-update.sh。';
  }
  if (is_readable($dir . '/host-update.log')) {
    $raw = preg_replace('/\x1b?\[[0-9;]*m/', '', (string)file_get_contents($dir . '/host-update.log'));
    $out['log'] = implode("\n", array_slice(preg_split('/\R/u', rtrim((string)$raw)), -80));
  }
  return $out;
}

function sm_nas_setup_status(): array {
  // Status of the NAS connection setup performed by the root agent. The page may collect
  // the connection here, but the SMB password is never stored or read back by this layer.
  $dir = '/updater';
  $out = [
    'available'   => false,
    'state'       => 'idle',
    'message'     => '',
    'updated'     => null,
    'key_created' => false,
    'log'         => '',
    'pending'     => false,
    'versions'    => SM_NAS_SMB_VERSIONS,
  ];
  if (!is_dir($dir) || !is_writable($dir)) {
    $out['message'] = '尚未啟用網頁設定。';
    return $out;
  }
  $out['available'] = is_file($dir . '/nas-webconfig.json');
  if (!$out['available']) {
    $out['message'] = '尚未啟用網頁設定 NAS。請在主機執行一次 helper-scripts/setup-nas-webconfig.sh。';
  }
  $out['pending'] = is_file($dir . '/nas-setup-request.json');
  if (is_readable($dir . '/nas-setup-status.json')) {
    $st = json_decode((string)file_get_contents($dir . '/nas-setup-status.json'), true);
    if (is_array($st)) {
      $out['state']       = (string)($st['state'] ?? 'idle');
      $out['message']     = (string)($st['message'] ?? $out['message']);
      $out['updated']     = isset($st['updated']) ? (int)$st['updated'] : null;
      $out['key_created'] = !empty($st['key_created']);
    }
  }
  if (is_readable($dir . '/nas-setup.log')) {
    $raw = preg_replace('/\x1b?\[[0-9;]*m/', '', (string)file_get_contents($dir . '/nas-setup.log'));
    $out['log'] = implode("\n", array_slice(preg_split('/\R/u', rtrim((string)$raw)), -40));
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
function sm_sender_domain(string $addr): string {
  $at=strrpos($addr,'@');
  $d=$at===false?$addr:substr($addr,$at+1);
  $d=rtrim(strtolower(trim($d)),'.');
  if(!preg_match('/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/',$d))throw new InvalidArgumentException('無法從寄件者取出有效網域：'.$addr);
  return $d;
}
// Mirror of the 全域名單 tab's client-side builder, re-derived server side so the
// quarantine tab never submits a hand-made regex: 'addr' pins the whole address,
// 'domain' the domain only, 'subdomain' the domain and anything below it.
function sm_sender_rule(string $cond,string $addr): string {
  $esc=fn(string $v)=>str_replace('/','\\/',preg_quote($v,null));
  if($cond==='addr')return '/^'.$esc(strtolower($addr)).'$/i';
  $d=sm_sender_domain($addr);
  if($cond==='subdomain')return '/@(?:[^@]+\\.)?'.$esc($d).'$/i';
  if($cond==='domain')return '/@'.$esc($d).'$/i';
  throw new InvalidArgumentException('不支援的比對條件。');
}
// Per-mailbox filterconf takes a glob, not a regex: native policy() turns '*' into
// '.*', so there is no anchored way to say "this domain and anything below it" in one
// entry -- '*example.com' would also match notexample.com. The per-mailbox scope
// therefore offers the exact address and the exact domain only, and 'subdomain' is
// rejected here as well as hidden in the page.
function sm_sender_policy_value(string $cond,string $addr): string {
  if($cond==='addr')return strtolower($addr);
  if($cond==='domain')return '*@'.sm_sender_domain($addr);
  throw new InvalidArgumentException('個別信箱名單只支援「精確地址」與「整個網域」；要連子網域一起擋請用全域名單。');
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
      $kind=$old['kind'] ?? 'regex';
      foreach($lines as $i=>$line){$line=trim($line);if($line==='' || str_starts_with($line,'#'))continue;
        if(!sm_valid_map_entry($kind,$line))throw new InvalidArgumentException('第 '.($i+1).' 行'.SM_MAP_KIND_HINT[$kind].'：'.$line);}
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
    case 'quarantine_copy':
      // 'add header' / 'rewrite subject' mail was already delivered to the mailbox's
      // Junk folder, so there is nothing to release -- but the admin still needs a
      // clean copy in the inbox after reviewing it. Native release reinjects through
      // the milter-bypassing listener, so the copy arrives without the spam header
      // and Sieve leaves it in INBOX. The Junk copy is untouched: the mailbox ends up
      // with both, which the confirmation text says.
      $id=$p['id'] ?? null;
      if(!(is_int($id) || (is_string($id) && ctype_digit($id))))throw new InvalidArgumentException('請指定要處理的郵件。');
      $id=(int)$id;
      $s=$pdo->prepare("SELECT `rcpt`,`action`,`sender`,`subject` FROM `quarantine` WHERE `id`=:id");$s->execute([':id'=>$id]);$row=$s->fetch(PDO::FETCH_ASSOC);
      if(!$row)throw new InvalidArgumentException('找不到該郵件，可能已刪除或過期。');
      if(($row['action'] ?? '')==='reject')throw new InvalidArgumentException('被拒收的郵件請用「放行」。');
      if(empty($row['rcpt']))throw new InvalidArgumentException('缺少收件人，無法投遞。');
      sm_backup($op,['id'=>$id,'rcpt'=>$row['rcpt'],'sender'=>$row['sender'],'subject'=>$row['subject'],'action'=>$row['action']],null);
      sm_native(fn()=>quarantine('edit',['action'=>'release','id'=>$id]));
      return ['message'=>'已複製一份到 '.$row['rcpt'].' 的收件匣；垃圾郵件匣裡原本那封仍在。'];
    case 'quarantine_list':
      // Add one sender condition taken from a held message. The address and the
      // recipient come from the quarantine row, never from the browser, so the page
      // cannot list an arbitrary third party. Both scopes reuse the same native
      // writers as the 全域名單 and 個別規則 tabs; the global scope does its
      // read-modify-write here so the quarantine tab needs no map baseline.
      $id=$p['id'] ?? null;
      if(!(is_int($id) || (is_string($id) && ctype_digit($id))))throw new InvalidArgumentException('請指定郵件。');
      $id=(int)$id;
      $kind=(string)($p['kind'] ?? '');if(!in_array($kind,['wl','bl'],true))throw new InvalidArgumentException('名單類型不正確。');
      $cond=(string)($p['cond'] ?? '');if(!in_array($cond,['addr','domain','subdomain'],true))throw new InvalidArgumentException('比對條件不正確。');
      $scope=(string)($p['scope'] ?? '');if(!in_array($scope,['global','rcpt'],true))throw new InvalidArgumentException('名單範圍不正確。');
      $s=$pdo->prepare("SELECT `sender`,`rcpt` FROM `quarantine` WHERE `id`=:id");$s->execute([':id'=>$id]);$row=$s->fetch(PDO::FETCH_ASSOC);
      if(!$row)throw new InvalidArgumentException('找不到該郵件，可能已刪除或過期。');
      $addr=strtolower(trim((string)$row['sender']));
      if($addr==='' || !filter_var($addr,FILTER_VALIDATE_EMAIL))throw new InvalidArgumentException('這封郵件的信封寄件者不是有效地址（'.($addr===''?'空寄件者':$addr).'），無法自動建立名單條目，請改用「全域名單」分頁手動填寫。');
      if($scope==='rcpt'){
        $object=(string)$row['rcpt'];
        if(!in_array($object,sm_targets(),true))throw new InvalidArgumentException('收件者 '.$object.' 不是本機信箱或網域，無法建立個別名單。');
        $value=sm_sender_policy_value($cond,$addr);
        foreach(sm_policies() as $existing)
          if($existing['object']===$object && $existing['option']===($kind==='wl'?'whitelist_from':'blacklist_from') && strcasecmp($existing['value'],$value)===0)
            throw new InvalidArgumentException($object.' 的'.($kind==='wl'?'白':'黑').'名單已有這筆條件：'.$value);
        sm_backup($op,null,['scope'=>'rcpt','object'=>$object,'kind'=>$kind,'value'=>$value]);
        sm_native(fn()=>policy('add','mailbox',['username'=>$object,'object_list'=>$kind,'object_from'=>$value]));
        return ['message'=>'已把 '.$value.' 加入 '.$object.' 的'.($kind==='wl'?'白':'黑').'名單（只影響這個信箱）。'];
      }
      $match=(string)($p['match'] ?? 'smtp');if(!in_array($match,['smtp','mime'],true))throw new InvalidArgumentException('比對對象不正確。');
      $file='global_'.$match.'_from_'.($kind==='wl'?'whitelist':'blacklist').'.map';
      $maps=sm_maps();if(!isset($maps[$file]))throw new RuntimeException('找不到名單檔案 '.$file.'。');
      $rule=sm_sender_rule($cond,$addr);
      $old=$maps[$file];
      foreach(preg_split('/\R/u',$old['content']) as $line)
        if(trim($line)===$rule)throw new InvalidArgumentException('「'.$old['label'].'」已有這條規則：'.$rule);
      $content=rtrim($old['content'],"\r\n")."\n".$rule."\n";
      if(strlen($content)>262144)throw new InvalidArgumentException('名單內容過長。');
      sm_backup($op,$old,['scope'=>'global','file'=>$file,'content'=>$content,'added'=>$rule]);
      sm_native(fn()=>rspamd_maps('edit',['map'=>[$file],'rspamd_map_data'=>$content]));
      $actual=sm_maps()[$file] ?? null;
      if(!$actual || !in_array($rule,array_map('trim',preg_split('/\R/u',$actual['content'])),true))throw new RuntimeException('名單回讀時找不到新增的規則，請到「全域名單」分頁確認。');
      return ['message'=>'已把 '.$rule.' 加入「'.$old['label'].'」（全域生效）。','map'=>$actual];
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
    case 'update_verify_request':
      // Re-run the post-update checks. Read-only on the host, so no passphrase; the root
      // agent only maps this to the fixed verify script and enforces a 2-minute gap.
      $dir='/updater';
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁更新。');
      if(is_file($dir.'/request.json'))throw new RuntimeException('已有一筆請求待處理，請稍候。');
      $us=sm_update_status();
      if(($us['state'] ?? '')==='running')throw new RuntimeException('更新正在進行中，結束後會自動驗證。');
      $v=$us['verify'] ?? [];
      if(($v['state'] ?? '')==='running')throw new RuntimeException('驗證正在進行中。');
      if(!empty($v['verified']) && time()-(int)$v['verified']<120)throw new RuntimeException('兩次驗證需間隔 2 分鐘，請稍後再試。');
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin','action'=>'verify'],JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.request.tmp';
      if(file_put_contents($tmp,$payload)===false)throw new RuntimeException('無法寫入驗證請求。');
      chmod($tmp,0600);
      if(!rename($tmp,$dir.'/request.json')){@unlink($tmp);throw new RuntimeException('無法送出驗證請求。');}
      return ['message'=>'已送出重新驗證，約 30 秒到 1 分鐘完成，結果會顯示在此頁。'];
    case 'backup_request':
      // Same contract as update_request: hand the job to the root agent, which verifies
      // the passphrase. The backup target is fixed on the host, so nothing the web layer
      // sends can redirect a copy of the mail somewhere else.
      $dir='/updater';
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁備份，請先在主機執行 setup-nas-backup.sh。');
      if(!is_file($dir.'/backup-target.json'))throw new RuntimeException('尚未設定 NAS，請先在主機執行 setup-nas-backup.sh。');
      // No passphrase here: a backup only ever writes one more encrypted copy to a
      // destination fixed on the host. The host agent rate-limits it instead, because the
      // real risk is repeated triggering interrupting mail.
      if(is_file($dir.'/backup-request.json'))throw new RuntimeException('已有一筆備份請求待處理，請稍候。');
      $bstatus=sm_nas_backup_status();
      if(($bstatus['state'] ?? '')==='running')throw new RuntimeException('備份正在進行中。');
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin']);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin'],JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.backup-request.tmp';
      if(file_put_contents($tmp,$payload)===false)throw new RuntimeException('無法寫入備份請求。');
      chmod($tmp,0600);
      if(!rename($tmp,$dir.'/backup-request.json')){@unlink($tmp);throw new RuntimeException('無法送出備份請求。');}
      return ['message'=>'已送出備份請求。過程中部分郵件服務會短暫停止，完成後此頁會顯示結果。'];
    case 'restore_request':
      // Three independent gates: the update passphrase (verified by the root agent), an
      // explicit component whitelist, and the admin retyping the exact backup name.
      $dir='/updater';
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁還原。');
      if(!is_file($dir.'/backup-target.json'))throw new RuntimeException('尚未設定 NAS。');
      $pass=(string)($p['passphrase'] ?? '');
      if($pass==='')throw new InvalidArgumentException('請輸入更新密碼。');
      if(strlen($pass)>256)throw new InvalidArgumentException('更新密碼過長。');
      $name=trim((string)($p['backup'] ?? ''));
      if(!preg_match('/^mailcow-[0-9][0-9-]*$/',$name))throw new InvalidArgumentException('請選擇要還原的備份。');
      if(trim((string)($p['confirm'] ?? ''))!==$name)throw new InvalidArgumentException('確認欄位必須與備份名稱完全相同。');
      $known=array_column(sm_nas_backup_status()['backups'] ?? [],'name');
      if($known && !in_array($name,$known,true))throw new InvalidArgumentException('這份備份不在 NAS 的清單中，請重新讀取後再試。');
      $comps=$p['components'] ?? [];
      if(!is_array($comps) || !$comps)throw new InvalidArgumentException('請至少選擇一個要還原的元件。');
      $comps=array_values(array_unique(array_map('strval',$comps)));
      foreach($comps as $c){
        if(!in_array($c,SM_RESTORE_WEB_COMPONENTS,true))
          throw new InvalidArgumentException('元件 '.$c.' 不能從網頁還原；信件類（vmail／crypt）請在主機執行。');
      }
      if(is_file($dir.'/restore-request.json'))throw new RuntimeException('已有一筆還原請求待處理，請稍候。');
      $rstatus=sm_nas_restore_status();
      if(($rstatus['state'] ?? '')==='running')throw new RuntimeException('還原正在進行中。');
      $bstate=sm_nas_backup_status();
      if(($bstate['state'] ?? '')==='running')throw new RuntimeException('備份正在進行中，請等它結束再還原。');
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin','backup'=>$name,'components'=>$comps]);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin','backup'=>$name,'components'=>$comps,'passphrase'=>$pass],JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.restore-request.tmp';
      if(file_put_contents($tmp,$payload)===false)throw new RuntimeException('無法寫入還原請求。');
      chmod($tmp,0600);
      if(!rename($tmp,$dir.'/restore-request.json')){@unlink($tmp);throw new RuntimeException('無法送出還原請求。');}
      return ['message'=>'已送出還原請求（'.$name.'：'.implode('、',$comps).'）。主機會驗證密碼、檢查備份完整性並先快照目前狀態，期間服務會中斷。'];
    case 'geo_request':
      // Opening a country is security-relevant, so it needs the update passphrase, which
      // the root agent verifies; it also re-validates every field before touching nft.
      $dir='/updater';
      $gs=sm_geo_status();
      if(empty($gs['configured']))throw new RuntimeException($gs['message'] ?: '尚未安裝登入地區限制。');
      if(!empty($gs['pending']))throw new RuntimeException('已有一筆登入地區變更待處理，請稍候。');
      $pass=(string)($p['passphrase'] ?? '');
      if($pass==='')throw new InvalidArgumentException('請輸入更新密碼。');
      if(strlen($pass)>256)throw new InvalidArgumentException('更新密碼過長。');
      $known=array_flip($gs['available_countries'] ?? []);
      $cc=[];
      foreach((array)($p['countries'] ?? []) as $c){
        $c=strtoupper((string)$c);
        if(!preg_match('/^[A-Z]{2}$/',$c) || !isset($known[$c]))throw new InvalidArgumentException('國家代碼不正確：'.$c);
        if(!in_array($c,$cc,true))$cc[]=$c;
      }
      $tmp=[];
      foreach((array)($p['temporary'] ?? []) as $e){
        if(!is_array($e))throw new InvalidArgumentException('臨時開放項目格式不正確。');
        $c=strtoupper((string)($e['cc'] ?? ''));$until=(int)($e['until'] ?? 0);
        if(!preg_match('/^[A-Z]{2}$/',$c) || !isset($known[$c]))throw new InvalidArgumentException('臨時開放的國家代碼不正確：'.$c);
        if($until<=time())continue;
        if($until>time()+90*86400+3600)throw new InvalidArgumentException('臨時開放最長 90 天。');
        $tmp[]=['cc'=>$c,'until'=>$until,'note'=>mb_substr(preg_replace('/[\x00-\x1f]/u','',(string)($e['note'] ?? '')),0,60)];
      }
      $enabled=!empty($p['enabled']);
      if($enabled && !$cc && !$tmp)throw new InvalidArgumentException('啟用時至少要開放一個國家，否則所有外部登入都會被擋。');
      if(count($cc)>60 || count($tmp)>60)throw new InvalidArgumentException('國家數量過多。');
      $policy=['enabled'=>$enabled,'countries'=>$cc,'temporary'=>$tmp];
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin','policy'=>$policy]);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin','policy'=>$policy,'passphrase'=>$pass],JSON_UNESCAPED_UNICODE);
      $tmpf=$dir.'/.geo-request.tmp';
      if(file_put_contents($tmpf,$payload)===false)throw new RuntimeException('無法寫入登入地區請求。');
      chmod($tmpf,0600);
      if(!rename($tmpf,$dir.'/geo-request.json')){@unlink($tmpf);throw new RuntimeException('無法送出登入地區請求。');}
      return ['message'=>'已送出登入地區變更，主機驗證密碼後約數秒內生效。'];
    case 'host_update_request':
      // Two actions only, both gated by the update passphrase that the root agent checks.
      // 'apply' restarts the container runtime; 'reboot' restarts the machine. Neither is
      // ever automatic, which is what the admin asked for.
      $dir='/updater';
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁主機更新。');
      if(!is_file($dir.'/host-status.json'))throw new RuntimeException('尚未設定主機更新，請先在主機執行 setup-host-update.sh。');
      $act=(string)($p['action'] ?? '');
      if(!in_array($act,['apply','reboot'],true))throw new InvalidArgumentException('不支援的動作。');
      $pass=(string)($p['passphrase'] ?? '');
      if($pass==='')throw new InvalidArgumentException('請輸入更新密碼。');
      if(strlen($pass)>256)throw new InvalidArgumentException('更新密碼過長。');
      if(is_file($dir.'/host-request.json'))throw new RuntimeException('已有一筆主機維護請求待處理，請稍候。');
      $hs=sm_host_update_status();
      if(in_array($hs['state'] ?? '',['applying','rebooting'],true))throw new RuntimeException('主機維護正在進行中。');
      if($act==='reboot' && empty($hs['reboot_required']))
        throw new InvalidArgumentException('目前沒有需要重開機才生效的更新，不需重開。');
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin','action'=>$act]);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin','action'=>$act,'passphrase'=>$pass],JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.host-request.tmp';
      if(file_put_contents($tmp,$payload)===false)throw new RuntimeException('無法寫入主機維護請求。');
      chmod($tmp,0600);
      if(!rename($tmp,$dir.'/host-request.json')){@unlink($tmp);throw new RuntimeException('無法送出主機維護請求。');}
      return ['message'=>$act==='apply'
        ?'已送出主機更新請求。容器執行環境會重啟，郵件服務短暫中斷，完成後此頁會顯示結果。'
        :'已送出重開機請求。主機驗證密碼後會立即重開，約 2～3 分鐘後恢復，此頁會暫時無法連線。'];
    case 'nas_setup_request':
      // The SMB password passes through here once, by explicit choice, so that the NAS can
      // be configured from the page. It is written straight to a 0600 request file that the
      // root agent shreds after use: never to Redis, the database, the audit trail or a log.
      $dir='/updater';
      $pass=(string)($p['passphrase'] ?? '');
      if($pass==='')throw new InvalidArgumentException('請輸入更新密碼。');
      if(strlen($pass)>256)throw new InvalidArgumentException('更新密碼過長。');
      $host=trim((string)($p['nas_host'] ?? ''));
      $share=trim((string)($p['nas_share'] ?? ''));
      $path=trim(trim((string)($p['nas_path'] ?? ''),'/'));
      $nuser=trim((string)($p['nas_user'] ?? ''));
      $domain=trim((string)($p['nas_domain'] ?? ''));
      $npass=(string)($p['nas_pass'] ?? '');
      $vers=trim((string)($p['nas_vers'] ?? '3.0'));
      $keep=trim((string)($p['keep'] ?? '8'));
      // Mirrors the host-side validation so the admin gets the error on the page instead
      // of having to read a log; the host checks again regardless.
      if(!preg_match('/^[A-Za-z0-9._-]{1,253}$/',$host))throw new InvalidArgumentException('伺服器位址只能是主機名稱或 IP。');
      if(!preg_match('/^[A-Za-z0-9._$ -]{1,80}$/',$share))throw new InvalidArgumentException('分享名稱含不允許的字元。');
      if($path!=='' && (!preg_match('~^[A-Za-z0-9._/-]{1,200}$~',$path) || strpos($path,'..')!==false))
        throw new InvalidArgumentException('子目錄只能是英數、點、底線、減號與斜線，且不可含 ..。');
      if(!preg_match('/^[A-Za-z0-9._@\\-]{1,128}$/',$nuser))throw new InvalidArgumentException('使用者名稱含不允許的字元。');
      if($domain!=='' && !preg_match('/^[A-Za-z0-9._-]{1,128}$/',$domain))throw new InvalidArgumentException('網域含不允許的字元。');
      if($npass==='')throw new InvalidArgumentException('請輸入 NAS 密碼。');
      if(strlen($npass)>256)throw new InvalidArgumentException('NAS 密碼過長。');
      if(preg_match('/[\r\n]/',$npass))throw new InvalidArgumentException('NAS 密碼不可含換行。');
      if(!in_array($vers,SM_NAS_SMB_VERSIONS,true))throw new InvalidArgumentException('SMB 版本不在允許清單內。');
      if(!preg_match('/^[1-9][0-9]?$/',$keep))throw new InvalidArgumentException('保留份數必須是 1-99 的整數。');
      // Preconditions come after validation so a bad field reports itself clearly.
      if(!is_dir($dir) || !is_writable($dir))throw new RuntimeException('尚未啟用網頁設定。');
      if(!is_file($dir.'/nas-webconfig.json'))throw new RuntimeException('尚未啟用網頁設定 NAS，請先在主機執行 setup-nas-webconfig.sh。');
      if(is_file($dir.'/nas-setup-request.json'))throw new RuntimeException('已有一筆設定請求待處理，請稍候。');
      $ns=sm_nas_setup_status();
      if(($ns['state'] ?? '')==='running')throw new RuntimeException('設定正在進行中。');
      // Audit the target only. The password must not end up in the audit trail.
      sm_backup($op,null,['actor'=>$_SESSION['mailcow_cc_username'] ?? 'admin',
        'target'=>'//'.$host.'/'.$share.($path!==''?'/'.$path:''),'user'=>$nuser,'vers'=>$vers,'keep'=>$keep]);
      $payload=json_encode(['ts'=>time(),'user'=>$_SESSION['mailcow_cc_username'] ?? 'admin',
        'passphrase'=>$pass,'nas_host'=>$host,'nas_share'=>$share,'nas_path'=>$path,
        'nas_user'=>$nuser,'nas_domain'=>$domain,'nas_pass'=>$npass,'nas_vers'=>$vers,'keep'=>$keep],
        JSON_UNESCAPED_UNICODE);
      $tmp=$dir.'/.nas-setup-request.tmp';
      $fh=@fopen($tmp,'w');
      if(!$fh)throw new RuntimeException('無法寫入設定請求。');
      @chmod($tmp,0600);
      $ok=fwrite($fh,$payload)!==false;
      fclose($fh);
      $payload=null;$npass=null;$pass=null;
      if(!$ok){@unlink($tmp);throw new RuntimeException('無法寫入設定請求。');}
      if(!rename($tmp,$dir.'/nas-setup-request.json')){@unlink($tmp);throw new RuntimeException('無法送出設定請求。');}
      return ['message'=>'已送出 NAS 設定請求。主機會驗證密碼、套用設定並實際測試掛載，約數秒到數十秒。'];
    case 'backup_notify_save':
      global $redis;
      $old=sm_backup_notify();
      $raw=trim((string)($p['value'] ?? ''));
      // Empty turns the failure notice off; the backup itself keeps running.
      $new=($raw==='')?'':implode(',',sm_parse_addresses($raw));
      sm_backup($op,$old,$new);
      try{$redis->Set('BACKUP_NOTIFY',$new);}catch(Throwable $e){throw new RuntimeException('無法儲存設定（Redis）。');}
      if(sm_backup_notify()!==$new)throw new RuntimeException('設定回讀不符，請重試。');
      return ['message'=>$new===''?'已關閉備份失敗通知。':'備份失敗通知收件人已更新為：'.$new,'notify'=>$new];
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

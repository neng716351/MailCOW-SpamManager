<?php
// Local addition — admin notification for INBOUND rejected mail.
//
// rspamd metadata_exporter (INBOUND_NOTIFY rule) POSTs here when a message addressed to a
// local mailbox is rejected and the sender is NOT one of our authenticated users. The copy
// itself is already stored by the native quarantine pipe (pipe.php), so this endpoint only
// sends the admin notice. Recipients are managed from the Spam Manager page (Redis).
header('Content-Type: text/plain');
require_once "vars.inc.php";
ini_set('error_reporting', 0);

// Derive our own hostname from mailcow's config so nothing site-specific is hardcoded.
$mc_host = getenv('MAILCOW_HOSTNAME');
if (!$mc_host) { $mc_host = $mailcow_hostname ?? 'localhost'; }

$NOTIFY_KEY     = 'REJECTED_HOLD_NOTIFY';
$NOTIFY_DEFAULT = '';   // empty = notifications off until an address is set on the page

try {
  $redis = new Redis();
  $redis->connect('redis-mailcow', 6379);
  $redis->auth(getenv("REDISPASS"));
} catch (Throwable $e) {
  error_log("INBOUND_NOTIFY: redis " . $e . PHP_EOL);
  http_response_code(504);
  exit;
}

try { $raw_list = $redis->Get($NOTIFY_KEY); } catch (Throwable $e) { $raw_list = false; }
$notify_to = array();
foreach (preg_split('/[\s,;]+/', ($raw_list !== false && $raw_list !== '') ? $raw_list : $NOTIFY_DEFAULT, -1, PREG_SPLIT_NO_EMPTY) as $addr) {
  if (filter_var($addr, FILTER_VALIDATE_EMAIL)) $notify_to[] = $addr;
}
if (!$notify_to) { echo "skip: no notify recipients configured"; exit; }

if (empty($_POST['metadata'])) {
  error_log("INBOUND_NOTIFY: missing metadata from rspamd" . PHP_EOL);
  http_response_code(400);
  exit;
}
$meta = json_decode($_POST['metadata'], true);
if (!is_array($meta)) {
  error_log("INBOUND_NOTIFY: cannot decode metadata JSON" . PHP_EOL);
  http_response_code(400);
  exit;
}

$subject = $meta['subject'] ?? '';
$score   = $meta['score']   ?? 0;
$rcpts   = $meta['rcpt']    ?? array();
$ip      = $meta['ip']      ?? 'unknown';
$action  = $meta['action']  ?? 'no action';
$sender  = $meta['from']    ?? '(empty)';
$symbols_json = json_encode($meta['symbols'] ?? array());
$virus   = (stripos($symbols_json, 'VIRUS_FOUND') !== false);

if ($action !== 'reject') { echo "skip: not reject"; exit; }

$syms = json_decode($symbols_json, true);
$sym_names = is_array($syms) ? implode(', ', array_slice(array_keys($syms), 0, 12)) : '';

$body  = "有一封寄給本機信箱的郵件被拒收。若判斷為誤判，可到管理介面放行。\r\n\r\n";
$body .= "寄件者：" . $sender . "\r\n";
$body .= "收件人：" . (is_array($rcpts) ? implode('、', $rcpts) : (string)$rcpts) . "\r\n";
$body .= "主旨：" . ($subject !== '' ? $subject : '（無主旨）') . "\r\n";
$body .= "來源 IP：" . $ip . "\r\n";
$body .= "分數：" . $score . ($virus ? "（⚠ 命中病毒掃描）" : "") . "\r\n";
$body .= "命中項目：" . ($sym_names !== '' ? $sym_names : '（無）') . "\r\n\r\n";
$body .= "處理（需管理員登入）：\r\n";
$body .= "https://" . $mc_host . "/admin/SpamManager#sm-rejected\r\n\r\n";
$body .= "只有「收件人為本機信箱且已留存」的郵件才能放行；SMTP 連線階段拒收沒有留存副本。\r\n";
$body .= "放行等於略過當初的攔截，請先確認郵件安全。\r\n";

$lines = array();
$lines[] = 'Subject: =?UTF-8?B?' . base64_encode('【收到的郵件被拒收】' . ($virus ? '（病毒）' : '')) . '?=';
$lines[] = 'From: Mail Guard <postmaster@' . $mc_host . '>';
$lines[] = 'To: ' . implode(', ', array_map(fn($a) => '<' . $a . '>', $notify_to));
$lines[] = 'Content-Type: text/plain; charset=UTF-8';
$lines[] = 'Content-Transfer-Encoding: base64';
$lines[] = '';
$msg = implode("\r\n", $lines) . chunk_split(base64_encode($body));

// Deliver through Postfix port 590 (milter-bypassing reinjection listener) to the local admin.
$fp = @fsockopen('postfix-mailcow', 590, $errno, $errstr, 5);
if (!$fp) $fp = @fsockopen('postfix', 590, $errno, $errstr, 5);
if (!$fp) { error_log("INBOUND_NOTIFY: connect failed: $errstr" . PHP_EOL); http_response_code(504); exit; }
stream_set_timeout($fp, 10);
$talk = array(array('220', "HELO inbound-notify\r\n"), array('250', "MAIL FROM:<>\r\n"));
foreach ($notify_to as $addr) { $talk[] = array('250', "RCPT TO:<" . $addr . ">\r\n"); }
$talk[] = array('250', "DATA\r\n");
$talk[] = array('354', $msg . "\r\n.\r\n");
$talk[] = array('250', "QUIT\r\n");
foreach ($talk as $step) {
  $resp = fgets($fp, 512);
  if (strpos((string)$resp, $step[0]) !== 0) {
    error_log("INBOUND_NOTIFY: SMTP expected $step[0], got " . trim((string)$resp) . PHP_EOL);
    fclose($fp);
    http_response_code(500);
    exit;
  }
  fwrite($fp, $step[1]);
}
fclose($fp);
echo "notified " . count($notify_to) . " recipient(s)";

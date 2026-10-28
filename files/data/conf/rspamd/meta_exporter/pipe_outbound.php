<?php
// Local addition — outbound reject hold.
// rspamd metadata_exporter (OUTBOUND_HOLD rule, multipart formatter) POSTs here when
// an AUTHENTICATED (local) sender's message is rejected. We keep a copy of the message
// for each EXTERNAL recipient in `outbound_hold` so an admin can review and release it
// to the customer from the Spam Manager page. The message is still rejected by Postfix;
// this only keeps a copy. Mirrors pipe.php's bootstrap; prerequisites are not included.
header('Content-Type: text/plain');
require_once "vars.inc.php";
ini_set('error_reporting', 0);

// Derive our own hostname from mailcow's config so nothing site-specific is hardcoded.
$mc_host = getenv('MAILCOW_HOSTNAME');
if (!$mc_host) { $mc_host = $mailcow_hostname ?? 'localhost'; }

$NOTIFY_TO_DEFAULT = '';                       // empty = notifications off until set on the page
$RETENTION_DAYS = 30;                          // opportunistic age-based cleanup

$dsn = $database_type . ":unix_socket=" . $database_sock . ";dbname=" . $database_name;
$opt = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false];
try {
  $pdo = new PDO($dsn, $database_user, $database_pass, $opt);
} catch (PDOException $e) {
  error_log("OUTBOUND_HOLD: " . $e . PHP_EOL);
  http_response_code(501);
  exit;
}
try {
  $redis = new Redis();
  $redis->connect('redis-mailcow', 6379);
  $redis->auth(getenv("REDISPASS"));
} catch (Throwable $e) {
  error_log("OUTBOUND_HOLD: redis " . $e . PHP_EOL);
  http_response_code(504);
  exit;
}

function oh_parse_email($email) {
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return false;
  $a = strrpos($email, '@');
  return array('local' => substr($email, 0, $a), 'domain' => strtolower(substr(substr($email, $a), 1)));
}

if (empty($_POST['metadata']) || !isset($_FILES['message']) || $_FILES['message']['error'] !== UPLOAD_ERR_OK) {
  error_log("OUTBOUND_HOLD: missing multipart parts from rspamd" . PHP_EOL);
  http_response_code(400);
  exit;
}
$meta = json_decode($_POST['metadata'], true);
if (!is_array($meta)) {
  error_log("OUTBOUND_HOLD: cannot decode metadata JSON" . PHP_EOL);
  http_response_code(400);
  exit;
}

$raw_data = file_get_contents($_FILES['message']['tmp_name']);
$raw_size = (int)$_FILES['message']['size'];

$qid     = $meta['qid']     ?? 'unknown';
$subject = $meta['subject'] ?? '';
$score   = $meta['score']   ?? 0;
$rcpts   = $meta['rcpt']    ?? array();
$user    = $meta['user']    ?? 'unknown';
$ip      = $meta['ip']      ?? 'unknown';
$action  = $meta['action']  ?? 'no action';
$sender  = $meta['from']    ?? '';
$symbols_json = json_encode($meta['symbols'] ?? array());
$virus   = (stripos($symbols_json, 'VIRUS_FOUND') !== false) ? 1 : 0;

// Only hold mail that was actually rejected and sent by an authenticated local user.
if ($action !== 'reject') { echo "skip: not reject"; exit; }
if (empty($user) || $user === 'unknown') { echo "skip: no auth user"; exit; }
if (empty($sender)) $sender = 'empty-env-from@localhost';

try {
  $max_size = (int)$redis->Get('Q_MAX_SIZE');
  if ($max_size > 0 && ($max_size * 1048576) < $raw_size) {
    error_log(sprintf("OUTBOUND_HOLD: message too large: %d b", $raw_size) . PHP_EOL);
    http_response_code(505);
    exit;
  }
} catch (RedisException $e) {
  error_log("OUTBOUND_HOLD: " . $e . PHP_EOL);
  http_response_code(504);
  exit;
}

// Keep only external recipients (domain not local to this mailcow). Local rcpts are
// handled by the inbound quarantine, not here.
$external = array();
foreach ($rcpts as $rcpt) {
  $rcpt = preg_replace('/^(.*?)\+.*(@.*)$/', '$1$2', $rcpt);
  $p = oh_parse_email($rcpt);
  if (!$p) continue;
  try {
    if ($redis->hGet('DOMAIN_MAP', $p['domain'])) continue; // local domain -> not outbound
  } catch (RedisException $e) { continue; }
  $external[] = $rcpt;
}
$external = array_values(array_unique($external));
if (!$external) { echo "skip: no external rcpt"; exit; }

$stored = array();
foreach ($external as $rcpt) {
  try {
    $stmt = $pdo->prepare("INSERT INTO `outbound_hold`
      (`qid`,`subject`,`score`,`ip`,`symbols`,`virus`,`sender`,`rcpt`,`msg`,`user`)
      VALUES (:qid,:subject,:score,:ip,:symbols,:virus,:sender,:rcpt,:msg,:user)");
    $stmt->execute(array(
      ':qid' => $qid, ':subject' => $subject, ':score' => $score, ':ip' => $ip,
      ':symbols' => $symbols_json, ':virus' => $virus, ':sender' => $sender,
      ':rcpt' => $rcpt, ':msg' => $raw_data, ':user' => $user,
    ));
    $stored[] = $rcpt;
  } catch (PDOException $e) {
    error_log("OUTBOUND_HOLD: insert failed for " . $rcpt . ": " . $e . PHP_EOL);
  }
}
if (!$stored) { http_response_code(500); echo "no rows stored"; exit; }

// Opportunistic age-based cleanup.
try {
  $pdo->prepare("DELETE FROM `outbound_hold` WHERE `created` < (NOW() - INTERVAL :days DAY)")->execute(array(':days' => $RETENTION_DAYS));
} catch (PDOException $e) { /* non-fatal */ }

// Notify the admin once per message (not per recipient). The recipient list is managed
// from the Spam Manager page and stored in Redis; fall back to the default if unset.
try { $notify_raw = $redis->Get('OUTBOUND_HOLD_NOTIFY'); } catch (Throwable $e) { $notify_raw = false; }
$notify_to = array();
foreach (preg_split('/[\s,;]+/', ($notify_raw !== false && $notify_raw !== '') ? $notify_raw : $NOTIFY_TO_DEFAULT, -1, PREG_SPLIT_NO_EMPTY) as $addr) {
  if (filter_var($addr, FILTER_VALIDATE_EMAIL)) $notify_to[] = $addr;
}
if (!$notify_to) $notify_to = array($NOTIFY_TO_DEFAULT);
oh_notify($notify_to, $sender, $user, $stored, $subject, $score, $virus, $symbols_json);
try {
  $pdo->prepare("UPDATE `outbound_hold` SET `notified`=1 WHERE `qid`=:qid AND `notified`=0")->execute(array(':qid' => $qid));
} catch (PDOException $e) { /* non-fatal */ }

echo "held " . count($stored) . " recipient(s)";

function oh_notify($to, $sender, $user, $rcpts, $subject, $score, $virus, $symbols_json) {
  global $mc_host;
  $to = is_array($to) ? $to : array($to);
  if (!$to) return;
  $syms = json_decode($symbols_json, true);
  $sym_names = is_array($syms) ? implode(', ', array_slice(array_keys($syms), 0, 12)) : '';
  $lines = array();
  $lines[] = 'Subject: =?UTF-8?B?' . base64_encode('【外寄郵件被攔截】等待放行決定') . '?=';
  $lines[] = 'From: Mail Guard <postmaster@' . $mc_host . '>';
  $lines[] = 'To: ' . implode(', ', array_map(fn($a) => '<' . $a . '>', $to));
  $lines[] = 'Content-Type: text/plain; charset=UTF-8';
  $lines[] = 'Content-Transfer-Encoding: base64';
  $lines[] = '';
  $body  = "有一封往外寄的郵件被攔截（已被拒收），等待管理員決定放行或刪除。\r\n\r\n";
  $body .= "寄件者（本機）：" . $sender . "\r\n";
  $body .= "驗證帳號：" . $user . "\r\n";
  $body .= "外部收件人：" . implode('、', $rcpts) . "\r\n";
  $body .= "主旨：" . ($subject !== '' ? $subject : '（無主旨）') . "\r\n";
  $body .= "分數：" . $score . ($virus ? "（⚠ 命中病毒掃描）" : "") . "\r\n";
  $body .= "命中項目：" . ($sym_names !== '' ? $sym_names : '（無）') . "\r\n\r\n";
  $body .= "請登入管理介面處理：\r\n";
  $body .= "https://" . $mc_host . "/admin/SpamManager#sm-outbound\r\n\r\n";
  $body .= "放行會將原信寄給外部收件人，等於略過當初的攔截，請先確認郵件安全。\r\n";
  $msg = implode("\r\n", $lines) . chunk_split(base64_encode($body));

  $fp = @fsockopen('postfix-mailcow', 590, $errno, $errstr, 5);
  if (!$fp) { $fp = @fsockopen('postfix', 590, $errno, $errstr, 5); }
  if (!$fp) { error_log("OUTBOUND_HOLD: notify connect failed: $errstr" . PHP_EOL); return; }
  stream_set_timeout($fp, 10);
  $talk = array(array('220', "HELO outbound-hold\r\n"), array('250', "MAIL FROM:<>\r\n"));
  foreach ($to as $addr) { $talk[] = array('250', "RCPT TO:<" . $addr . ">\r\n"); }
  $talk[] = array('250', "DATA\r\n");
  $talk[] = array('354', $msg . "\r\n.\r\n");
  $talk[] = array('250', "QUIT\r\n");
  foreach ($talk as $step) {
    $resp = fgets($fp, 512);
    if (strpos((string)$resp, $step[0]) !== 0) { error_log("OUTBOUND_HOLD: notify SMTP expected $step[0], got " . trim((string)$resp) . PHP_EOL); fclose($fp); return; }
    fwrite($fp, $step[1]);
  }
  fclose($fp);
}

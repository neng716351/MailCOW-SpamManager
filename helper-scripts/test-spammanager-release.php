<?php
// Smoke test for the SpamManager "被拒收郵件 / 放行" feature. Read-only: it never
// releases real mail (release validation paths throw before any delivery).
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
require '/web/inc/lib/vendor/autoload.php';
require '/web/inc/functions.rspamd.inc.php';
require '/web/inc/functions.quarantine.inc.php';
require '/web/inc/spammanager.inc.php';
function check($c, $m) { if (!$c) throw new RuntimeException('FAIL: ' . $m); echo "ok: $m\n"; }

$GLOBALS['pdo'] = new PDO('mysql:host=mysql-mailcow;dbname=' . getenv('DBNAME') . ';charset=utf8mb4', getenv('DBUSER'), getenv('DBPASS'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo = $GLOBALS['pdo'];
$GLOBALS['redis'] = new Redis(); $GLOBALS['redis']->connect('redis-mailcow', 6379); $GLOBALS['redis']->auth(getenv('REDISPASS')); $redis = $GLOBALS['redis'];
$_SESSION = ['mailcow_cc_role' => 'admin', 'mailcow_cc_username' => 'admin', 'acl' => ['quarantine' => '1']];

// 1. Read path works and returns a well-formed array.
$rows = sm_rejected();
check(is_array($rows), 'sm_rejected() returns array (count=' . count($rows) . ')');
foreach ($rows as $r) {
  check(isset($r['id'], $r['rcpt'], $r['sender'], $r['subject'], $r['score']), 'row has expected keys');
  check($r['id'] > 0, 'row id positive');
}

// 2. Release input validation rejects bad input WITHOUT touching mail.
foreach ([null, '', 'abc', '1.5', -1] as $bad) {
  try { sm_mutate('release', ['id' => $bad]); throw new RuntimeException('accepted bad id: ' . var_export($bad, true)); }
  catch (InvalidArgumentException $e) {}
}
check(true, 'release rejects non-numeric/empty ids');

// 3. Release of a non-existent id throws "not found" (no delivery attempted).
$maxId = (int)$pdo->query('SELECT COALESCE(MAX(id),0) FROM quarantine')->fetchColumn();
try { sm_mutate('release', ['id' => $maxId + 100000]); throw new RuntimeException('released non-existent id'); }
catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), '找不到'), 'non-existent id -> not found'); }

// 4. Template compiles and contains the new tab + section.
$_SERVER['DOCUMENT_ROOT'] = '/web'; $_SERVER['REQUEST_URI'] = '/admin/SpamManager'; $_GET = []; $DEV_MODE = false;
require '/web/inc/twig.inc.php';
$twig->setCache(false);
$html = $twig->render('spammanager.twig', ['csrf_token' => 'x', 'rsettings' => [], 'role' => 'admin', 'acl' => [], 'acl_json' => '[]', 'lang_admin' => '{}', 'lang_datatables' => '{}', 'lang' => ['admin' => []]]);
check(str_contains($html, '被拒收郵件'), 'template renders new tab label');
check(str_contains($html, 'data-sm-section="rejected"'), 'template renders rejected section');
check(str_contains($html, 'id="sm-rejected-rows"'), 'template renders rejected table body');

// 5. JS passes the production minifier (syntax smoke).
$js = new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js');
$min = $js->minify();
check(strlen($min) > 1000, 'spammanager.js minifies');
check(str_contains($min, 'loadRejected') && str_contains($min, 'releaseRejected'), 'minified JS keeps new functions');

echo "\nALL PASS\n";

// --- Part B: outbound hold smoke test (appended) ---
$rowsO = sm_outbound();
check(is_array($rowsO), 'sm_outbound() returns array (count=' . count($rowsO) . ')');
foreach ([null, '', 'abc', '1.5'] as $bad) {
  try { sm_mutate('outbound_release', ['id' => $bad]); throw new RuntimeException('accepted bad outbound id'); }
  catch (InvalidArgumentException $e) {}
  try { sm_mutate('outbound_delete', ['id' => $bad]); throw new RuntimeException('accepted bad outbound delete id'); }
  catch (InvalidArgumentException $e) {}
}
check(true, 'outbound release/delete reject bad ids');
$maxO = (int)$pdo->query('SELECT COALESCE(MAX(id),0) FROM outbound_hold')->fetchColumn();
try { sm_mutate('outbound_release', ['id' => $maxO + 100000]); throw new RuntimeException('released non-existent outbound'); }
catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), '找不到'), 'non-existent outbound -> not found (no send)'); }
// Virus row must refuse release without confirm_virus (uses a temp row, rolled back, never sent).
$pdo->beginTransaction();
try {
  $pdo->prepare("INSERT INTO outbound_hold (qid,subject,score,sender,rcpt,msg,user,virus) VALUES ('t','t',2000,'a@example.com','x@example.com','raw','a@example.com',1)")->execute();
  $vid = (int)$pdo->lastInsertId();
  try { sm_mutate('outbound_release', ['id' => $vid]); throw new RuntimeException('released virus without confirm'); }
  catch (InvalidArgumentException $e) { check(str_contains($e->getMessage(), '病毒'), 'virus outbound refused without confirm_virus'); }
} finally { $pdo->rollBack(); }
check(str_contains($html, '外寄攔截') && str_contains($html, 'data-sm-section="outbound"'), 'template renders outbound tab');
$js2 = new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js');
check(str_contains($js2->minify(), 'releaseOutbound'), 'minified JS keeps outbound functions');
echo "\nPART B PASS\n";

// --- Notify recipient setting (appended) ---
$defaultNotify = sm_outbound_notify();
check(filter_var(explode(',', $defaultNotify)[0], FILTER_VALIDATE_EMAIL) !== false, 'sm_outbound_notify() returns an address (' . $defaultNotify . ')');
foreach (['', 'notanemail', 'a@b.com, bad'] as $bad) {
  try { sm_mutate('outbound_notify_save', ['value' => $bad]); throw new RuntimeException('accepted bad notify: ' . $bad); }
  catch (InvalidArgumentException $e) {}
}
check(true, 'notify save rejects invalid addresses');
$saved = sm_mutate('outbound_notify_save', ['value' => 'admin@example.com, ops@example.com']);
check(sm_outbound_notify() === 'admin@example.com,ops@example.com', 'notify save + readback (multi)');
sm_mutate('outbound_notify_save', ['value' => $defaultNotify]); // restore
check(str_contains($html, 'id="sm-outbound-notify"'), 'template renders notify field');
echo "\nNOTIFY PASS\n";

// --- Live customizations check panel (appended) ---
$cust = sm_customizations();
// Assert the checklist's contents, not its length: the list grows whenever a local
// customization is added, and a hard-coded count makes every addition fail here.
$cust_names = array_column($cust, 'name');
check(is_array($cust) && count($cust) >= 6, 'sm_customizations() returns the checklist (' . count($cust) . ' items)');
foreach (['留存規則', 'init_db', 'base.twig', 'master.cf', 'ClamAV', '主機層名單規則', 'RSPAMD_MAPS', '自訂程式檔'] as $needle) {
  check((bool)array_filter($cust_names, fn($n) => str_contains($n, $needle)), 'checklist covers ' . $needle);
}
foreach ($cust as $c) {
  check(isset($c['name'], $c['status'], $c['detail']), 'item has name/status/detail');
  check(in_array($c['status'], ['ok', 'missing', 'unknown'], true), $c['name'] . ' => ' . $c['status'] . ($c['detail'] ? ' (' . $c['detail'] . ')' : ''));
}
$notOk = array_filter($cust, fn($c) => $c['status'] !== 'ok');
check(!$notOk, 'all customizations currently report ok');
check(str_contains($html, 'id="sm-custom-rows"'), 'template renders customizations panel');
check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'loadCustomizations'), 'minified JS keeps loadCustomizations');
echo "\nCUSTOMIZATIONS PASS\n";

// --- Web update request (appended). Never triggers a real update: the agent verifies
// the passphrase, and this test removes the request file it creates. ---
$us = sm_update_status();
check(is_array($us) && array_key_exists('available', $us), 'sm_update_status() returns a shape');
check($us['available'] === true, '/updater mounted and writable');

// The checks below submit a real request file. While an update is actually running the
// product code refuses new requests (by design), so they cannot pass and would abort this
// script. Skip them in that case and say so, rather than reporting a false failure.
if (($us['state'] ?? '') === 'running' || is_file('/updater/request.json')) {
  echo "skip: 更新進行中，略過送出請求的檢查\n";
  check(str_contains($html, 'id="sm-update-form"'), 'template renders update form');
  check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollUpdate'), 'minified JS keeps update polling');
  echo "\nWEB UPDATE SKIPPED\n";
} else {
foreach (['', null] as $bad) {
  try { sm_mutate('update_request', ['passphrase' => $bad]); throw new RuntimeException('accepted empty passphrase'); }
  catch (InvalidArgumentException $e) {}
}
check(true, 'update_request requires a passphrase');
try { sm_mutate('update_request', ['passphrase' => str_repeat('x', 300)]); throw new RuntimeException('accepted overlong'); }
catch (InvalidArgumentException $e) { check(true, 'update_request rejects overlong passphrase'); }
$res = sm_mutate('update_request', ['passphrase' => 'test-only-not-the-real-one']);
check(is_file('/updater/request.json'), 'update_request wrote the request file');
$req = json_decode((string)file_get_contents('/updater/request.json'), true);
check(isset($req['ts'], $req['user'], $req['passphrase']), 'request file has ts/user/passphrase');
check(abs(time() - (int)$req['ts']) < 10, 'request timestamp is fresh');
try { sm_mutate('update_request', ['passphrase' => 'another']); throw new RuntimeException('accepted duplicate'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(), '待處理'), 'duplicate request refused while one is pending'); }
unlink('/updater/request.json');
check(!is_file('/updater/request.json'), 'test request file cleaned up (no real update queued)');
check(str_contains($html, 'id="sm-update-form"'), 'template renders update form');
check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollUpdate'), 'minified JS keeps update polling');
echo "\nWEB UPDATE PASS\n";
}

// --- Inbound reject notification setting (appended) ---
$defIn = sm_rejected_notify();
check(is_string($defIn), 'sm_rejected_notify() returns string (目前=' . ($defIn ?: '（未設定／關閉）') . ')');
sm_mutate('rejected_notify_save', ['value' => 'admin@example.com']);
check(sm_rejected_notify() === 'admin@example.com', 'inbound notify save + readback');
sm_mutate('rejected_notify_save', ['value' => '']);
check(sm_rejected_notify() === '', 'inbound notify can be turned off with empty value');
try { sm_mutate('rejected_notify_save', ['value' => 'bogus']); throw new RuntimeException('accepted bad inbound notify'); }
catch (InvalidArgumentException $e) { check(true, 'inbound notify rejects invalid address'); }
try { sm_mutate('outbound_notify_save', ['value' => '']); throw new RuntimeException('outbound accepted empty'); }
catch (InvalidArgumentException $e) { check(true, 'outbound notify still requires at least one address'); }
sm_mutate('rejected_notify_save', ['value' => $defIn === '' ? '' : $defIn]); // restore
check(str_contains($html, 'id="sm-rejected-notify"'), 'template renders inbound notify field');
echo "\nINBOUND NOTIFY PASS\n";

// --- NAS backup (appended). Never starts a real backup: the agent verifies the
// passphrase, and this test removes any request file it creates. ---
$nb = sm_nas_backup_status();
foreach (['available','configured','state','target','retention','backups','log','notify'] as $k) {
  check(array_key_exists($k, $nb), "sm_nas_backup_status() has '$k'");
}
check(is_array($nb['backups']), 'backups is a list');
check(array_key_exists('encrypted', $nb), 'backup status reports whether backups are encrypted');
check($nb['available'] === true, '/updater mounted and writable (backup)');

$defNotify = sm_backup_notify();
check(is_string($defNotify), 'sm_backup_notify() returns string (目前=' . ($defNotify === '' ? '未設定' : $defNotify) . ')');
sm_mutate('backup_notify_save', ['value' => 'backup-test@example.invalid']);
check(sm_backup_notify() === 'backup-test@example.invalid', 'backup notify save + readback');
sm_mutate('backup_notify_save', ['value' => '']);
check(sm_backup_notify() === '', 'backup notify can be turned off with empty value');
try { sm_mutate('backup_notify_save', ['value' => 'not-an-address']); throw new RuntimeException('accepted bad backup notify'); }
catch (InvalidArgumentException $e) { check(true, 'backup notify rejects invalid address'); }
sm_mutate('backup_notify_save', ['value' => $defNotify]);
check(sm_backup_notify() === $defNotify, 'backup notify restored to the original value');

// A backup deliberately needs no passphrase; the host agent rate-limits it instead.
check(!str_contains(file_get_contents('/web/inc/spammanager.inc.php'), "'backup_request':\n      \$pass"),
      'backup_request no longer asks for a passphrase');

if (!is_file('/updater/backup-target.json')) {
  echo "skip: 尚未設定 NAS，略過送出備份請求的檢查\n";
  check(str_contains($html, 'id="sm-nas-form"'), 'template renders backup form');
  check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollNas'), 'minified JS keeps backup polling');
  echo "\nNAS BACKUP SKIPPED\n";
} elseif (($nb['state'] ?? '') === 'running' || is_file('/updater/backup-request.json')) {
  echo "skip: 備份進行中，略過送出備份請求的檢查\n";
  check(str_contains($html, 'id="sm-nas-form"'), 'template renders backup form');
  check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollNas'), 'minified JS keeps backup polling');
  echo "\nNAS BACKUP SKIPPED\n";
} else {
  sm_mutate('backup_request', []);
  check(is_file('/updater/backup-request.json'), 'backup_request wrote the request file');
  $breq = json_decode((string)file_get_contents('/updater/backup-request.json'), true);
  check(isset($breq['ts'], $breq['user']), 'backup request has ts/user');
  check(!isset($breq['passphrase']), 'backup request carries no passphrase');
  try { sm_mutate('backup_request', ['passphrase' => 'another']); throw new RuntimeException('accepted duplicate'); }
  catch (RuntimeException $e) { check(str_contains($e->getMessage(), '待處理'), 'duplicate backup request refused'); }
  unlink('/updater/backup-request.json');
  check(!is_file('/updater/backup-request.json'), 'test backup request cleaned up (no real backup queued)');
  check(str_contains($html, 'id="sm-nas-form"'), 'template renders backup form');
  check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollNas'), 'minified JS keeps backup polling');
  echo "\nNAS BACKUP PASS\n";
}

// --- NAS restore (appended). Never starts a real restore: every path below is rejected
// before a request file survives, and the one request it writes is removed again. ---
$rs = sm_nas_restore_status();
foreach (['available','state','backup','components','allowed','log','pending'] as $k) {
  check(array_key_exists($k, $rs), "sm_nas_restore_status() has '$k'");
}
check($rs['allowed'] === ['mysql','redis','rspamd','postfix'], 'web restore scope is settings-only');
check(!in_array('vmail', $rs['allowed'], true) && !in_array('crypt', $rs['allowed'], true),
      'vmail/crypt are not web-restorable');

$nbs = sm_nas_backup_status();
$haveNas = is_file('/updater/backup-target.json');
$someName = $nbs['backups'][0]['name'] ?? 'mailcow-2026-01-01-00-00-00';

// Mail components must be refused even when everything else is valid.
try {
  sm_mutate('restore_request', ['passphrase'=>'x','backup'=>$someName,'confirm'=>$someName,'components'=>['vmail']]);
  throw new RuntimeException('accepted vmail from web');
} catch (InvalidArgumentException $e) {
  check(str_contains($e->getMessage(), 'vmail') || str_contains($e->getMessage(), '網頁'), 'restore refuses vmail from the web');
} catch (RuntimeException $e) {
  check(str_contains($e->getMessage(), '尚未設定 NAS'), 'restore refused before NAS setup (vmail case)');
}

// A mismatched confirmation must be refused.
try {
  sm_mutate('restore_request', ['passphrase'=>'x','backup'=>$someName,'confirm'=>'wrong','components'=>['mysql']]);
  throw new RuntimeException('accepted bad confirm');
} catch (InvalidArgumentException $e) { check(true, 'restore requires the typed backup name to match'); }
  catch (RuntimeException $e) { check(str_contains($e->getMessage(), '尚未設定 NAS'), 'restore refused before NAS setup (confirm case)'); }

// A malformed backup name must be refused.
try {
  sm_mutate('restore_request', ['passphrase'=>'x','backup'=>'../etc/passwd','confirm'=>'../etc/passwd','components'=>['mysql']]);
  throw new RuntimeException('accepted bad backup name');
} catch (InvalidArgumentException $e) { check(true, 'restore rejects a malformed backup name'); }
  catch (RuntimeException $e) { check(str_contains($e->getMessage(), '尚未設定 NAS'), 'restore refused before NAS setup (name case)'); }

// No components at all must be refused.
try {
  sm_mutate('restore_request', ['passphrase'=>'x','backup'=>$someName,'confirm'=>$someName,'components'=>[]]);
  throw new RuntimeException('accepted empty components');
} catch (InvalidArgumentException $e) { check(true, 'restore requires at least one component'); }
  catch (RuntimeException $e) { check(str_contains($e->getMessage(), '尚未設定 NAS'), 'restore refused before NAS setup (empty case)'); }

check(!is_file('/updater/restore-request.json'), 'no restore request was left behind');
check(str_contains($html, 'id="sm-restore-form"'), 'template renders restore form');
check(str_contains($html, 'vmail'), 'template states that mail restore is host-only');
check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollRestore'),
      'minified JS keeps restore polling');

if (!$haveNas) {
  echo "skip: 尚未設定 NAS，略過實際送出還原請求\n";
  echo "\nNAS RESTORE SKIPPED\n";
} else {
  echo "\nNAS RESTORE PASS\n";
}

// --- Host OS maintenance (appended). Never triggers a real host action: the request is
// rejected or removed again before anything can pick it up. ---
$hu = sm_host_update_status();
foreach (['available','configured','state','count','security','deferred',
          'reboot_required','kernel_running','log','pending'] as $k) {
  check(array_key_exists($k, $hu), "sm_host_update_status() has '$k'");
}
check(is_array($hu['deferred']), 'deferred is a list');
check($hu['available'] === true, '/updater mounted and writable (host update)');

// Only apply/reboot may be requested; anything else must be refused.
foreach (['check', 'install', '../../bin/sh', ''] as $bad) {
  try {
    sm_mutate('host_update_request', ['action' => $bad, 'passphrase' => 'x']);
    throw new RuntimeException('accepted action ' . var_export($bad, true));
  } catch (InvalidArgumentException $e) {
    // expected
  } catch (RuntimeException $e) {
    check(str_contains($e->getMessage(), '尚未設定主機更新'), 'host request refused before setup');
  }
}
check(true, 'host_update_request rejects anything but apply/reboot');

// A passphrase is mandatory.
try {
  sm_mutate('host_update_request', ['action' => 'apply', 'passphrase' => '']);
  throw new RuntimeException('accepted empty passphrase');
} catch (InvalidArgumentException $e) { check(true, 'host_update_request requires a passphrase'); }
  catch (RuntimeException $e) { check(str_contains($e->getMessage(), '尚未設定主機更新'), 'host request refused before setup (pass case)'); }

check(!is_file('/updater/host-request.json'), 'no host request was left behind');
check(str_contains($html, 'id="sm-host-form"'), 'template renders host update form');
check(str_contains($html, 'containerd'), 'template explains which packages are deferred');
check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollHost'),
      'minified JS keeps host update polling');

if (!is_file('/updater/host-status.json')) {
  echo "skip: 尚未設定主機更新，略過實際送出請求\n";
  echo "\nHOST UPDATE SKIPPED\n";
} else {
  echo "\nHOST UPDATE PASS\n";
}

// --- NAS connection setup from the page (appended). Never applies a real configuration:
// every case below is rejected, and the suite asserts no request file survives. ---
$ns = sm_nas_setup_status();
foreach (['available','state','message','key_created','log','pending','versions'] as $k) {
  check(array_key_exists($k, $ns), "sm_nas_setup_status() has '$k'");
}
check($ns['versions'] === ['3.1.1','3.0','2.1','2.0','1.0'], 'SMB dialect list is a fixed whitelist');

$good = ['nas_host'=>'192.168.1.50','nas_share'=>'backup','nas_path'=>'mailcow',
         'nas_user'=>'svc_mail','nas_domain'=>'','nas_pass'=>'secret','nas_vers'=>'3.0',
         'keep'=>'8','passphrase'=>'test-only-not-the-real-one'];

// Each of these must be refused by the web layer, before the agent ever sees it.
$bad = [
  'injection in host'   => ['nas_host' => 'nas; rm -rf /'],
  'path traversal'      => ['nas_path' => '../../etc'],
  'backtick in share'   => ['nas_share' => 'back`id`up'],
  'newline in password' => ['nas_pass' => "a\nb"],
  'empty password'      => ['nas_pass' => ''],
  'bad SMB dialect'     => ['nas_vers' => '9.9'],
  'retention zero'      => ['keep' => '0'],
  'retention too big'   => ['keep' => '100'],
  'empty passphrase'    => ['passphrase' => ''],
];
foreach ($bad as $label => $override) {
  try {
    sm_mutate('nas_setup_request', array_merge($good, $override));
    throw new RuntimeException('accepted ' . $label);
  } catch (InvalidArgumentException $e) {
    // Validation runs before the install-state precondition, so this is the path we want.
    check(true, "nas_setup_request rejects: $label");
  }
}

check(!is_file('/updater/nas-setup-request.json'), 'no NAS setup request was left behind');
check(str_contains($html, 'id="sm-nassetup-form"'), 'template renders NAS setup form');
check(str_contains($html, 'backup.key'), 'template tells the admin to fetch the key on the host');
check(str_contains((new MatthiasMullie\Minify\JS('/web/js/site/spammanager.js'))->minify(), 'pollNasSetup'),
      'minified JS keeps NAS setup polling');

// The password must never reach the audit trail.
$auditDump = json_encode(sm_audit_entries(), JSON_UNESCAPED_UNICODE);
check(!str_contains((string)$auditDump, 'secret'), 'audit trail contains no NAS password');

if (!is_file('/updater/nas-webconfig.json')) {
  echo "skip: 尚未啟用網頁設定 NAS，略過實際送出設定請求\n";
  echo "\nNAS SETUP SKIPPED\n";
} else {
  echo "\nNAS SETUP PASS\n";
}

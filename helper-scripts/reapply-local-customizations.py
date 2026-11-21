#!/usr/bin/env python3
"""Re-apply this host's local mailcow customizations after an upstream update.

update.sh runs `git merge -X theirs`, so a tracked file we modified can be reverted to
the upstream version whenever upstream touches the same lines. Untracked files (the
Spam Manager set, pipe_outbound.php) and gitignored files (clamav whitelist) survive on
their own and are only verified here.

Every patch is anchor-based and idempotent: it detects whether the customization is
already present and, if not, applies it to the *current* upstream file so upstream
improvements are kept. If an anchor is missing (upstream restructured the file), the
patch is reported as NEEDS-MANUAL and the file is left untouched rather than guessed at.

Usage:  reapply-local-customizations.py --check      # report only, change nothing
        reapply-local-customizations.py --apply      # apply what is missing
"""
import argparse
import re
import os
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OK, APPLIED, MANUAL, MISSING = 'OK', 'APPLIED', 'NEEDS-MANUAL', 'MISSING'
results = []


def record(name, status, detail=''):
    results.append((name, status, detail))


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


BACKUP_ROOT = os.path.join(ROOT, '.local-customization-backups')


def write(path, text):
    # Keep backups out of the web root: nginx 404s .twig and .php but happily
    # serves a .twig.pre-reapply-* copy as plain text next to the original.
    rel = os.path.relpath(path, ROOT).replace(os.sep, '__')
    os.makedirs(BACKUP_ROOT, mode=0o700, exist_ok=True)
    backup = os.path.join(BACKUP_ROOT, f'{rel}.pre-reapply-{time.strftime("%Y%m%d-%H%M%S")}')
    shutil.copy2(path, backup)
    # read() normalises CRLF to LF; write the file back in the line endings it had, or
    # every patch silently rewrites the whole file (upstream pipe.php is CRLF).
    with open(path, 'rb') as fh:
        crlf = b'\r\n' in fh.read()
    with open(path, 'w', encoding='utf-8', newline='\r\n' if crlf else '\n') as fh:
        fh.write(text)
    return backup


MARKER_MULTIMAP = '# BEGIN local host-level lists (Spam Manager)'

MULTIMAP_BLOCK = """
# BEGIN local host-level lists (Spam Manager)
# Local addition 2026-11-03: the global address lists above cannot express a source
# IP, a sending host name or an ASN, so these add those conditions for the Spam
# Manager page. Scores mirror the global address lists (+/-2050 = force the action).
# There is deliberately no ASN allowlist: whitelisting a whole ISP bypasses filtering
# for every one of its customers. Whitelist that provider's IP ranges in ip_wl.map.
GLOBAL_IP_BL {
  type = "ip";
  map = "${LOCAL_CONFDIR}/custom/global_ip_blacklist.map";
  score = 2050;
  description = "Source IP is on the local blacklist";
  symbols_set = ["GLOBAL_IP_BL"];
}

# Local addition 2026-11-13: block mail by the DOMAIN of any link in the body.
# Phishing rotates sender addresses freely but reuses its landing page, so the link
# domain is the durable identifier. 'url' matches the host of every extracted URL;
# the map holds bare domains (one per line), which also cover their subdomains.
GLOBAL_URL_BL {
  type = "url";
  filter = "tld";
  map = "${LOCAL_CONFDIR}/custom/global_url_blacklist.map";
  score = 2050;
  description = "A link in the message points at a locally blacklisted domain";
  symbols_set = ["GLOBAL_URL_BL"];
}

GLOBAL_HELO_WL {
  type = "helo";
  map = "${LOCAL_CONFDIR}/custom/global_helo_whitelist.map";
  regexp = true;
  score = -2050;
  description = "Sending host HELO is on the local allowlist";
  symbols_set = ["GLOBAL_HELO_WL"];
}

GLOBAL_HELO_BL {
  type = "helo";
  map = "${LOCAL_CONFDIR}/custom/global_helo_blacklist.map";
  regexp = true;
  score = 2050;
  description = "Sending host HELO is on the local blacklist";
  symbols_set = ["GLOBAL_HELO_BL"];
}

GLOBAL_HOSTNAME_WL {
  type = "hostname";
  map = "${LOCAL_CONFDIR}/custom/global_hostname_whitelist.map";
  regexp = true;
  score = -2050;
  description = "Sending host reverse DNS name is on the local allowlist";
  symbols_set = ["GLOBAL_HOSTNAME_WL"];
}

GLOBAL_HOSTNAME_BL {
  type = "hostname";
  map = "${LOCAL_CONFDIR}/custom/global_hostname_blacklist.map";
  regexp = true;
  score = 2050;
  description = "Sending host reverse DNS name is on the local blacklist";
  symbols_set = ["GLOBAL_HOSTNAME_BL"];
}
# END local host-level lists (Spam Manager)
"""

REGISTRY_BLOCK = """
    // Local addition 2026-11-03: host-level regex lists for the Spam Manager page.
    'Sending Host HELO Allowlist' => 'global_helo_whitelist.map',
    'Sending Host HELO Denylist' => 'global_helo_blacklist.map',
    'Sending Host rDNS Allowlist' => 'global_hostname_whitelist.map',
    'Sending Host rDNS Denylist' => 'global_hostname_blacklist.map'
  ),
  // Local addition 2026-11-03: these are NOT regex maps, so they get their own keys.
  // rspamd_maps('edit') scans every key, so they stay writable; the native maps page
  // reads only ['regex'], so it is unchanged and these are edited from Spam Manager.
  'ip' => array(
    'Source IP Allowlist' => 'ip_wl.map',
    'Source IP Denylist' => 'global_ip_blacklist.map'
  ),
  'asn' => array(
    'Sender ASN Denylist' => 'bad_asn.map'
  ),
  // Local addition 2026-11-13: link-domain denylist. Plain domains, not regex --
  // multimap's url/tld filter already reduces every link to its registrable domain,
  // so one entry also covers that domain's subdomains.
  'url' => array(
    'Link Domain Denylist' => 'global_url_blacklist.map'
  )
);"""

# --- individual customizations -------------------------------------------------

def patch_metadata_exporter(apply_changes):
    """Widen the quarantine selector (inbound) and add the OUTBOUND_HOLD rule."""
    name = 'rspamd metadata_exporter.conf'
    path = os.path.join(ROOT, 'data/conf/rspamd/local.d/metadata_exporter.conf')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    original = text

    # Since 2026-11-13: keep a copy of EVERY inbound message to a local mailbox, so mail
    # that merely got greylisted or passed clean is still reviewable in Spam Manager.
    widened_body = """return function(task)
  if task:has_symbol('MAILCOW_AUTH') then return false end
  if task:has_symbol('RCPT_MAILCOW_DOMAIN') then return true end
  -- 2026-11-16: rspamd stops running rules once the score passes reject, so a
  -- blacklist hit (GLOBAL_URL_BL and friends, 2050 points) can end the scan before
  -- RCPT_MAILCOW_DOMAIN is ever evaluated. Keep every non-authenticated reject;
  -- pipe.php drops recipients that are not ours.
  return task:get_metric_action('default') == 'reject'
end"""

    # 1. inbound: replace whatever upstream shipped with the keep-everything selector
    if widened_body not in text:
        start = text.find("  reject_no_global_bl = <<EOD")
        end = text.find('EOD;', start)
        if start == -1 or end == -1:
            return record(name, MANUAL, 'reject_no_global_bl block not found')
        head = "  reject_no_global_bl = <<EOD\n"
        marker = ("-- Local change: keep a copy of EVERY inbound message addressed to a local\n"
                  "-- mailbox, not only the ones that were acted on, so an admin can read what\n"
                  "-- was actually delivered. Copies are purged by Q_MAX_AGE.\n")
        text = text[:start] + head + marker + widened_body + '\n' + text[end:]

    # 2. outbound: OUTBOUND_HOLD rule + its selector
    if 'OUTBOUND_HOLD' not in text:
        anchor = """  PUSHOVERMAIL {
    backend = "http";
    url = "http://nginx:9081/pushover.php";
    selector = "mailcow_rcpt";
    formatter = "multipart";
  }"""
        if anchor not in text:
            return record(name, MANUAL, 'PUSHOVERMAIL rule anchor not found')
        text = text.replace(anchor, anchor + """
  OUTBOUND_HOLD {
    backend = "http";
    url = "http://nginx:9081/pipe_outbound.php";
    selector = "outbound_reject";
    formatter = "multipart";
  }""")

    # 3. inbound: admin notification rule for mail rejected towards a local mailbox
    if 'INBOUND_NOTIFY' not in text:
        anchor = """  OUTBOUND_HOLD {
    backend = "http";
    url = "http://nginx:9081/pipe_outbound.php";
    selector = "outbound_reject";
    formatter = "multipart";
  }"""
        if anchor not in text:
            return record(name, MANUAL, 'OUTBOUND_HOLD rule anchor not found')
        text = text.replace(anchor, anchor + """
  INBOUND_NOTIFY {
    backend = "http";
    url = "http://nginx:9081/pipe_inbound_notify.php";
    selector = "inbound_reject";
    formatter = "multipart";
  }""", 1)

    if 'outbound_reject = <<EOD' not in text:
        tail = widened_body + '\nEOD;'
        if tail not in text:
            return record(name, MANUAL, 'widened selector tail not found for selector insert')
        text = text.replace(tail, tail + """
  outbound_reject = <<EOD
-- Local addition: hold OUTBOUND (authenticated local sender) mail that was rejected,
-- so an admin can review and release it to the external recipient.
return function(task)
  local action = task:get_metric_action('default')
  if action ~= 'reject' then return false end
  if task:has_symbol('MAILCOW_AUTH') then
    return true
  end
  return false
end
EOD;""", 1)

    if 'inbound_reject = <<EOD' not in text:
        tail = """  if task:has_symbol('MAILCOW_AUTH') then
    return true
  end
  return false
end
EOD;"""
        if tail not in text:
            return record(name, MANUAL, 'outbound selector tail not found for inbound selector insert')
        text = text.replace(tail, tail + """
  inbound_reject = <<EOD
-- Local addition: notify the admin when mail addressed to a local mailbox is rejected.
-- Excludes our own authenticated senders (those go through OUTBOUND_HOLD instead).
return function(task)
  local action = task:get_metric_action('default')
  if action ~= 'reject' then return false end
  if task:has_symbol('MAILCOW_AUTH') then return false end
  if task:has_symbol('RCPT_MAILCOW_DOMAIN') then
    return true
  end
  return false
end
EOD;""", 1)

    if text == original:
        return record(name, OK)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


ALIAS_SCORE_BLOCK = r'''// Local addition 2026-11-13: per-ALIAS spam thresholds.
//
// ucl_rcpts($object, 'mailbox') expands a mailbox into its aliases and never emits the
// object itself, so putting an alias address into `filterconf` yields a settings block
// with no rcpt match -- i.e. one that applies to ALL mail. Aliases therefore get their
// own blocks here, with an explicit rcpt regexp. Config lives in alias-spamlevels.json
// so adding another alias needs no code change.
$alias_levels_file = __DIR__ . '/alias-spamlevels.json';
if (is_readable($alias_levels_file)) {
  $alias_levels = json_decode((string)file_get_contents($alias_levels_file), true);
  if (is_array($alias_levels)) {
    $alias_index = 0;
    foreach ($alias_levels as $alias_addr => $levels) {
      if (!is_string($alias_addr) || $alias_addr === '' || $alias_addr[0] === '_') continue;
      if (!is_array($levels)) continue;
      if (!filter_var($alias_addr, FILTER_VALIDATE_EMAIL)) continue;
      $parsed = parse_email($alias_addr);
      if (empty($parsed['local']) || empty($parsed['domain'])) continue;
      $actions = array();
      foreach (array('reject' => 'reject', 'greylist' => 'greylist', 'add_header' => '"add header"') as $key => $ucl_key) {
        if (isset($levels[$key]) && is_numeric($levels[$key])) $actions[$ucl_key] = (float)$levels[$key];
      }
      if (!$actions) continue;
      $alias_index++;
      // Emit the same two rcpt forms the blocks above use: a plus-addressing regexp and
      // the bare address. Mirroring mailcow's own style matters -- '\+' inside a UCL
      // double-quoted string does not survive as a regexp quantifier escape, so the
      // plus form must be written as '[+]'. NOTE: this file's parse_email() returns
      // 'domain' WITH its leading '@'.
      $local_re = str_replace('/', '\\/', $parsed['local']);
      $domain_re = str_replace('/', '\\/', $parsed['domain']);
?>
  alias_score_<?=$alias_index;?> {
    priority = 4;
    rcpt = "/^<?=$local_re;?>[+].*<?=$domain_re;?>$/i";
    rcpt = "<?=str_replace('/', '\\/', $alias_addr);?>";
    apply "default" {
      ALIAS_SPAMLEVEL = 0.0;
      actions {
<?php foreach ($actions as $ucl_key => $value) { ?>
        <?=$ucl_key;?> = <?=rtrim(rtrim(number_format($value, 2, '.', ''), '0'), '.');?>;
<?php } ?>
      }
    }
    symbols [
      "ALIAS_SPAMLEVEL"
    ]
  }
<?php
    }
  }
}

'''


def patch_settings_php(apply_changes):
    """Re-add per-ALIAS spam thresholds to the rspamd settings dynmap."""
    name = 'rspamd dynmaps settings.php'
    path = os.path.join(ROOT, 'data/conf/rspamd/dynmaps/settings.php')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    original = text

    # 1. Fold alias-spamlevels.json's mtime into the map freshness check. Without this
    #    rspamd keeps serving its cached copy and edits to the file never take effect.
    if '$alias_levels_mtime' not in text:
        anchor_fresh = """if (empty($db_update_time)) {
  $db_update_time = 1572048000;
}"""
        if anchor_fresh not in text:
            return record(name, MANUAL, 'db_update_time block not found')
        text = text.replace(anchor_fresh, anchor_fresh + """
// Local addition 2026-11-13: per-alias thresholds live in alias-spamlevels.json, not in
// a database table, so editing that file would not move the timestamp above -- rspamd
// would keep serving its cached copy of this map indefinitely.
$alias_levels_mtime = @filemtime(__DIR__ . '/alias-spamlevels.json');
if ($alias_levels_mtime) {
  $db_update_time = max((int)$db_update_time, (int)$alias_levels_mtime);
}""", 1)

    # 2. Emit a settings block per alias. ucl_rcpts() expands a mailbox into its aliases
    #    and never emits the object itself, so an alias in `filterconf` would produce a
    #    block with NO rcpt match -- one that applies to ALL mail.
    if 'alias_score_' not in text:
        anchor_scores = """$stmt = $pdo->query("SELECT DISTINCT `object` FROM `filterconf` WHERE `option` = 'highspamlevel' OR `option` = 'lowspamlevel'");"""
        if anchor_scores not in text:
            return record(name, MANUAL, 'custom scores query not found')
        text = text.replace(anchor_scores, ALIAS_SCORE_BLOCK + anchor_scores, 1)

    if text == original:
        return record(name, OK)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


PIPE_PASSIVE_BLOCK = """// Local change 2026-11-13: the QUARANTINE selector now keeps a copy of every inbound
    // message, so mail that was NOT acted on must never reach the per-mailbox digest --
    // a mailbox whose quarantine_category is 'all' would otherwise be mailed an hourly
    // list of its own normal mail. Pre-mark those copies as notified; they stay fully
    // visible to the admin UI.
    $passive_actions = array('no action', 'greylist', 'soft reject');
    $pre_notified = in_array($action, $passive_actions, true) ? 1 : 0;
    """


def patch_pipe_php(apply_changes):
    """Keep passive quarantine copies out of the per-mailbox digest (quarantine_notify.py)."""
    name = 'rspamd meta_exporter pipe.php'
    path = os.path.join(ROOT, 'data/conf/rspamd/meta_exporter/pipe.php')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    original = text

    if '$pre_notified' not in text:
        # Anchor on the statement's shape, not its exact column list: upstream added
        # `qhash` in 2026-11 and the literal-string match broke (NEEDS-MANUAL on update).
        m = re.search(r'(\$stmt = \$pdo->prepare\("INSERT INTO `quarantine` \()([^)]*)(\)\s*VALUES \()([^)]*)(\)"\);)', text)
        if not m:
            return record(name, MANUAL, 'quarantine INSERT statement not found')
        if '`notified`' in m.group(2):
            return record(name, MANUAL, 'upstream INSERT already sets notified; review by hand')
        stmt = m.group(1) + m.group(2) + ', `notified`' + m.group(3) + m.group(4) + ', :notified' + m.group(5)
        text = text[:m.start()] + PIPE_PASSIVE_BLOCK + stmt + text[m.end():]
        b = re.search(r"\n(\s*)':action' => \$action,", text[m.start():])
        if not b:
            return record(name, MANUAL, "':action' bind not found after the INSERT")
        pos = m.start() + b.end()
        text = text[:pos] + '\n' + b.group(1) + "':notified' => $pre_notified," + text[pos:]

    if text == original:
        return record(name, OK)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


def patch_init_db(apply_changes):
    """Re-add the outbound_hold table definition so it survives container rebuilds."""
    name = 'web init_db.inc.php (outbound_hold)'
    path = os.path.join(ROOT, 'data/web/inc/init_db.inc.php')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    if '"outbound_hold"' in text:
        return record(name, OK)
    anchor = """          "key" => array(
            "qhash" => array("qhash")
          )
        ),
        "attr" => "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC"
      ),
"""
    if anchor not in text:
        return record(name, MANUAL, 'quarantine table anchor not found')
    block = """      // Local addition: holds a copy of OUTBOUND (authenticated-sender) mail that was
      // rejected, for admin review/release from the Spam Manager page.
      "outbound_hold" => array(
        "cols" => array(
          "id" => "INT NOT NULL AUTO_INCREMENT",
          "qid" => "VARCHAR(30) NOT NULL DEFAULT 'unknown'",
          "subject" => "VARCHAR(500)",
          "score" => "FLOAT(8,2)",
          "ip" => "VARCHAR(50)",
          "symbols" => "JSON",
          "virus" => "TINYINT(1) NOT NULL DEFAULT '0'",
          "sender" => "VARCHAR(255) NOT NULL DEFAULT 'unknown'",
          "rcpt" => "VARCHAR(255)",
          "msg" => "LONGTEXT",
          "user" => "VARCHAR(255) NOT NULL DEFAULT 'unknown'",
          "released" => "TINYINT(1) NOT NULL DEFAULT '0'",
          "decided_by" => "VARCHAR(255)",
          "notified" => "TINYINT(1) NOT NULL DEFAULT '0'",
          "created" => "DATETIME(0) NOT NULL DEFAULT NOW(0)",
        ),
        "keys" => array(
          "primary" => array(
            "" => array("id")
          ),
          "key" => array(
            "created" => array("created")
          )
        ),
        "attr" => "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC"
      ),
"""
    text = text.replace(anchor, anchor + block, 1)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


def patch_base_twig(apply_changes):
    """Re-add the Spam Manager entry to the admin navigation menu."""
    name = 'web base.twig (Spam Manager 選單入口)'
    path = os.path.join(ROOT, 'data/web/templates/base.twig')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    if '/admin/SpamManager' in text:
        return record(name, OK)
    anchor = """            <li><a href="/quarantine" class="dropdown-item {% if is_uri('quarantine') %}active{% endif %}">{{ lang.header.quarantine }}</a></li>
"""
    if anchor not in text:
        return record(name, MANUAL, 'quarantine menu entry anchor not found')
    entry = """            {# Local addition: entry point for the custom Spam Manager page #}
            <li><a href="/admin/SpamManager" class="dropdown-item {% if is_uri('SpamManager') %}active{% endif %}">Spam Manager</a></li>
"""
    text = text.replace(anchor, anchor + entry, 1)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)} — 記得清除 Twig 快取並重啟 php-fpm')


def patch_qhandler_twig(apply_changes):
    """Re-add the preview link on the native release/delete confirmation page.

    Digest reports sent before the preview feature existed only carry
    /qhandler links, so this is how their recipients reach the body.
    """
    name = 'web qhandler.twig (放行確認頁查看內容)'
    path = os.path.join(ROOT, 'data/web/templates/qhandler.twig')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    if 'qpreview.php' in text:
        return record(name, OK)
    anchor = """        <div id="qactions">
"""
    if anchor not in text:
        return record(name, MANUAL, 'qactions anchor not found')
    entry = """          {# Local addition: let the recipient read the body before confirming #}
          <div class="mb-3">
            <a class="btn btn-outline-primary" href="/qpreview.php?hash={{ hash }}" rel="noreferrer">查看郵件內容</a>
          </div>
"""
    text = text.replace(anchor, anchor + entry, 1)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)} — 記得清除 Twig 快取並重啟 php-fpm')


def patch_master_cf(apply_changes):
    """Re-apply the whitelist TCP map lifetime extension on the 10027 spawn service."""
    name = 'postfix master.cf (10027 spawn lifetime)'
    path = os.path.join(ROOT, 'data/conf/postfix/master.cf')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    if 'command_time_limit=30d' in text:
        return record(name, OK)
    anchor = '127.0.0.1:10027 inet n n n - 0 spawn user=nobody argv=/usr/local/bin/whitelist_forwardinghosts.sh'
    if anchor not in text:
        return record(name, MANUAL, '10027 spawn line not found in expected form')
    replacement = ('# Persistent TCP map sessions: allow 30 days; individual HTTP requests are bounded by the local hook.\n'
                   '127.0.0.1:10027 inet n n n - 0 spawn\n'
                   '  -o command_time_limit=30d\n'
                   '  user=nobody argv=/usr/local/bin/whitelist_forwardinghosts.sh')
    text = text.replace(anchor, replacement, 1)
    if not apply_changes:
        return record(name, APPLIED, '(dry-run: would patch)')
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


def patch_multimap(apply_changes):
    """Re-add the host-level lists (source IP, HELO, reverse DNS) used by Spam Manager."""
    name = 'rspamd multimap.conf (host-level lists)'
    path = os.path.join(ROOT, 'data/conf/rspamd/local.d/multimap.conf')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    # The block is self-contained and appended at the end, so no upstream anchor is
    # needed: either the marker is there or the whole block goes back on.
    end_marker = '# END local host-level lists (Spam Manager)'
    if MARKER_MULTIMAP in text and 'GLOBAL_URL_BL' in text:
        return record(name, OK, '6 rules present (incl. link-domain denylist)')
    if MARKER_MULTIMAP in text:
        # An older block without GLOBAL_URL_BL: swap the whole block for the current one.
        s = text.index(MARKER_MULTIMAP); e = text.find(end_marker, s)
        if e == -1:
            return record(name, MANUAL, 'block start found but END marker missing')
        if not apply_changes:
            return record(name, APPLIED, 'would replace the block to add GLOBAL_URL_BL')
        text = text[:s].rstrip('\n') + '\n' + MULTIMAP_BLOCK.lstrip('\n') + text[e + len(end_marker):].lstrip('\n')
        backup = write(path, text)
        return record(name, APPLIED, f'added GLOBAL_URL_BL, backup: {os.path.basename(backup)}')
    if not apply_changes:
        return record(name, APPLIED, 'would re-append the host-level rules')
    backup = write(path, text.rstrip('\n') + '\n' + MULTIMAP_BLOCK)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


def patch_rspamd_maps_registry(apply_changes):
    """Register the host-level maps in $RSPAMD_MAPS so they stay editable from the page."""
    name = 'vars.inc.php ($RSPAMD_MAPS registry)'
    path = os.path.join(ROOT, 'data/web/inc/vars.inc.php')
    if not os.path.isfile(path):
        return record(name, MISSING, path)
    text = read(path)
    if 'global_helo_whitelist.map' in text and 'global_url_blacklist.map' in text:
        return record(name, OK, 'host-level maps registered (incl. link-domain denylist)')
    if 'global_helo_whitelist.map' in text:
        # Older registry without the 'url' kind: add it before the closing of $RSPAMD_MAPS.
        start = text.find('$RSPAMD_MAPS = array(')
        close = text.find('\n);', start)
        if start == -1 or close == -1:
            return record(name, MANUAL, 'cannot locate end of $RSPAMD_MAPS to add the url kind')
        if not apply_changes:
            return record(name, APPLIED, 'would register global_url_blacklist.map')
        head = text[:close].rstrip()
        if not head.endswith(','):
            head += ','
        text = head + "\n  'url' => array(\n    'Link Domain Denylist' => 'global_url_blacklist.map'\n  )" + text[close:]
        backup = write(path, text)
        return record(name, APPLIED, f'added url kind, backup: {os.path.basename(backup)}')
    start = text.find('$RSPAMD_MAPS = array(')
    if start == -1:
        return record(name, MANUAL, '$RSPAMD_MAPS declaration not found')
    close = text.find('\n  )\n);', start)
    if close == -1:
        return record(name, MANUAL, 'end of the regex map array not found')
    if not apply_changes:
        return record(name, APPLIED, 'would register the host-level maps')
    head = text[:close]
    # The upstream list may have grown, so comma-terminate whatever its last entry is.
    if not head.rstrip().endswith(','):
        head = head.rstrip() + ','
    text = head + REGISTRY_BLOCK + text[close + len('\n  )\n);'):]
    backup = write(path, text)
    record(name, APPLIED, f'backup: {os.path.basename(backup)}')


def check_clamav_whitelist():
    """data/conf/clamav/whitelist.ign2 is gitignored, so local false-positive exceptions
    survive updates. Only report whether one exists; its contents are site-specific."""
    name = 'clamav whitelist.ign2 (local exceptions)'
    path = os.path.join(ROOT, 'data/conf/clamav/whitelist.ign2')
    if not os.path.isfile(path):
        return record(name, OK, 'none configured')
    n = sum(1 for l in read(path).splitlines() if l.strip() and not l.startswith('#'))
    record(name, OK, f'{n} exception(s), gitignored, survives updates')


def check_untracked_files():
    """These are untracked additions; update.sh leaves them alone. Verify presence."""
    expected = [
        'data/web/admin/SpamManager.php',
        'data/web/admin/SpamManagerApi.php',
        'data/web/qpreview.php',
        'data/web/inc/spammanager.inc.php',
        'data/web/inc/impersonation.inc.php',
        'data/web/js/site/spammanager.js',
        'data/web/js/site/spammanager.translations.js',
        'data/web/js/site/impersonation.js',
        'data/web/templates/spammanager.twig',
        'data/web/templates/spammanager-controls.twig',
        'data/conf/rspamd/meta_exporter/pipe_outbound.php',
        'data/conf/rspamd/meta_exporter/pipe_inbound_notify.php',
        'data/conf/rspamd/custom/global_ip_blacklist.map',
        'data/conf/rspamd/custom/global_helo_whitelist.map',
        'data/conf/rspamd/custom/global_helo_blacklist.map',
        'data/conf/rspamd/custom/global_hostname_whitelist.map',
        'data/conf/rspamd/custom/global_hostname_blacklist.map',
        'data/conf/rspamd/custom/global_url_blacklist.map',
        'data/conf/rspamd/dynmaps/alias-spamlevels.json',
        'helper-scripts/mailcow-geo-agent.py',
        'helper-scripts/setup-geo-allowlist.sh',
    ]
    missing = [p for p in expected if not os.path.isfile(os.path.join(ROOT, p))]
    if missing:
        record('custom web/rspamd files', MISSING, ', '.join(missing))
    else:
        record('custom web/rspamd files', OK, f'{len(expected)} files present (untracked)')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='report only, change nothing')
    group.add_argument('--apply', action='store_true', help='apply missing customizations')
    args = ap.parse_args()
    apply_changes = args.apply

    patch_metadata_exporter(apply_changes)
    patch_pipe_php(apply_changes)
    patch_settings_php(apply_changes)
    patch_init_db(apply_changes)
    patch_base_twig(apply_changes)
    patch_qhandler_twig(apply_changes)
    patch_master_cf(apply_changes)
    patch_multimap(apply_changes)
    patch_rspamd_maps_registry(apply_changes)
    check_clamav_whitelist()
    check_untracked_files()

    width = max(len(n) for n, _, _ in results)
    print()
    for name, status, detail in results:
        print(f'  {name.ljust(width)}  {status:<12} {detail}')
    print()

    changed = [r for r in results if r[1] == APPLIED]
    manual = [r for r in results if r[1] in (MANUAL, MISSING)]
    if manual:
        print('需要人工確認：')
        for name, status, detail in manual:
            print(f'  - {name}: {status} {detail}')
        print()
    if changed and apply_changes:
        print('已重新套用設定。請重啟受影響的服務（rspamd / postfix / php-fpm）。')
    elif changed:
        print('以上項目在實際執行 --apply 時會被重新套用。')
    elif manual:
        print('其餘自訂設定都在；上面列出的項目需要人工處理。')
    else:
        print('所有本機自訂設定都在，無需重新套用。')
    return 2 if manual else 0


if __name__ == '__main__':
    sys.exit(main())

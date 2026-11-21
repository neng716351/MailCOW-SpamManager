#!/usr/bin/env python3
"""Login-region allowlist for mailcow (root agent).

Only the ports that accept a password are restricted to source countries the admin
allows. Port 25 (inbound mail from any vendor) and port 80 (https redirect and Let's
Encrypt validation) are never touched: neither accepts a login (25 was verified to
advertise no AUTH -- master.cf runs `smtpd pass` with smtpd_sasl_auth_enable=no).

Security model, same as the other web-triggered agents:
  * the web UI (php-fpm, uid 82) can only drop a request file; it never runs nft;
  * a request is honoured only with the update passphrase, verified here against the
    root-only salted hash, so a stolen admin session cannot open the server to the
    world;
  * every field is re-validated here; the policy that is enforced lives root-only in
    /etc/mailcow-geo/policy.json, never in the web-writable directory.

Fail-safe rules:
  * private ranges (office LAN, containers, loopback) are always allowed;
  * if the country data is missing or implausibly small, the ruleset is NOT changed --
    an empty allowlist would lock every external user out.

Modes:
  --request       process <updater>/geo-request.json (systemd path unit)
  --apply         re-apply the stored policy: drops expired temporary entries,
                  refreshes the status page (systemd timer, every 10 minutes)
  --refresh-data  download the five RIR delegation files (systemd timer, daily)
  --disable       emergency switch from the host: remove the table, mark disabled
"""
import argparse
import bisect
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

MAILCOW_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPDATER_DIR = os.path.join(MAILCOW_DIR, 'data', 'updater')
REQUEST = os.path.join(UPDATER_DIR, 'geo-request.json')
STATUS = os.path.join(UPDATER_DIR, 'geo-status.json')
CONF_DIR = '/etc/mailcow-geo'
POLICY = os.path.join(CONF_DIR, 'policy.json')
DATA_DIR = '/var/lib/mailcow-geo'
DATA = os.path.join(DATA_DIR, 'countries.json')
SECRET_FILE = '/etc/mailcow-updater/passphrase.hash'
TABLE = 'mailcow_geo'
LOG_PREFIX = 'mcgeo-drop '
MAX_AGE = 180                 # seconds a web request stays valid
MAX_TEMP_DAYS = 90            # a temporary opening may last at most this long
MAX_COUNTRIES = 60

# Ports that accept a password. 25 and 80 are deliberately absent (see docstring).
PROTECTED_PORTS = {
    110: 'POP3', 995: 'POP3S', 143: 'IMAP', 993: 'IMAPS',
    465: 'SMTPS 寄信', 587: 'Submission 寄信', 4190: 'Sieve 篩選規則',
    443: 'HTTPS（webmail／管理介面／ActiveSync）',
}
ALWAYS_ALLOW_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
                   '169.254.0.0/16', '100.64.0.0/10']
ALWAYS_ALLOW_V6 = ['::1/128', 'fe80::/10', 'fc00::/7']

RIR_URLS = {
    'apnic': 'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
    'arin': 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ripencc': 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
    'lacnic': 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
    'afrinic': 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
}
# Below this many IPv4 addresses a country's data is treated as broken for enforcement
# purposes (Taiwan holds ~35 million). Small countries can still be ADDED; only the
# "is it safe to enforce at all" check uses the largest permanent country.
MIN_SANE_V4 = 100000
CC_RE = re.compile(r'^[A-Z]{2}$')


def now():
    return int(time.time())


def log(msg):
    subprocess.run(['logger', '-t', 'mailcow-geo', msg], check=False)


def atomic_write(path, data, mode=0o644):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            v = json.load(fh)
        return v if isinstance(v, type(default)) else default
    except Exception:
        return default


# ---------------------------------------------------------------- country data
def refresh_data():
    """Download all five RIR files and store {cc: {"v4": [cidr...], "v6": [...]}}."""
    out = {}
    for rir, url in RIR_URLS.items():
        req = urllib.request.Request(url, headers={'User-Agent': 'mailcow-geo-allowlist/1.0'})
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = resp.read().decode('ascii', 'replace')
        n = 0
        for line in body.splitlines():
            if not line or line[0] == '#':
                continue
            f = line.split('|')
            if len(f) < 7 or f[6] not in ('allocated', 'assigned'):
                continue
            cc, typ, start, value = f[1].upper(), f[2], f[3], f[4]
            if not CC_RE.match(cc):
                continue
            try:
                if typ == 'ipv4':
                    first = ipaddress.IPv4Address(start)
                    last = first + int(value) - 1
                    nets = ipaddress.summarize_address_range(first, last)
                    out.setdefault(cc, {'v4': [], 'v6': []})['v4'].extend(str(x) for x in nets)
                elif typ == 'ipv6':
                    net = ipaddress.IPv6Network(f'{start}/{int(value)}', strict=False)
                    out.setdefault(cc, {'v4': [], 'v6': []})['v6'].append(str(net))
                else:
                    continue
                n += 1
            except ValueError:
                continue
        if n < 1000:
            raise RuntimeError(f'{rir} 的資料只有 {n} 筆，疑似下載不完整')
    tw = sum(ipaddress.ip_network(c).num_addresses for c in out.get('TW', {}).get('v4', []))
    if tw < MIN_SANE_V4:
        raise RuntimeError(f'台灣只有 {tw} 個 IPv4 位址，資料異常，保留舊資料')
    os.makedirs(DATA_DIR, mode=0o755, exist_ok=True)
    atomic_write(DATA, {'fetched': now(), 'countries': out})
    return len(out)


def load_data():
    d = read_json(DATA, {})
    return d.get('countries', {}), d.get('fetched')


def v4_count(data, cc):
    return sum(ipaddress.ip_network(c).num_addresses for c in data.get(cc, {}).get('v4', []))


# ---------------------------------------------------------------- policy
def empty_policy():
    return {'enabled': False, 'countries': ['TW'], 'temporary': [], 'changed': None, 'by': None}


def validate_policy(p, data):
    """Return a clean policy dict or raise ValueError with a user-facing message."""
    if not isinstance(p, dict):
        raise ValueError('設定格式不正確')
    enabled = bool(p.get('enabled'))
    countries = p.get('countries', [])
    if not isinstance(countries, list) or len(countries) > MAX_COUNTRIES:
        raise ValueError('常駐開放國家清單格式不正確')
    clean_cc = []
    for c in countries:
        c = str(c).upper()
        if not CC_RE.match(c):
            raise ValueError(f'國家代碼不正確：{c}')
        if c not in data:
            raise ValueError(f'找不到國家 {c} 的 IP 資料')
        if c not in clean_cc:
            clean_cc.append(c)
    temps = p.get('temporary', [])
    if not isinstance(temps, list) or len(temps) > MAX_COUNTRIES:
        raise ValueError('臨時開放清單格式不正確')
    clean_t = []
    limit = now() + MAX_TEMP_DAYS * 86400 + 3600
    for t in temps:
        if not isinstance(t, dict):
            raise ValueError('臨時開放項目格式不正確')
        c = str(t.get('cc', '')).upper()
        if not CC_RE.match(c) or c not in data:
            raise ValueError(f'臨時開放的國家代碼不正確：{c}')
        try:
            until = int(t.get('until', 0))
        except (TypeError, ValueError):
            raise ValueError('臨時開放的到期時間不正確')
        if until <= now():
            continue                      # already expired: just drop it
        if until > limit:
            raise ValueError(f'臨時開放最長 {MAX_TEMP_DAYS} 天')
        note = re.sub(r'[\x00-\x1f]', '', str(t.get('note', '')))[:60]
        clean_t.append({'cc': c, 'until': until, 'note': note})
    if enabled and not clean_cc and not clean_t:
        raise ValueError('啟用時至少要開放一個國家，否則所有外部登入都會被擋')
    if enabled and not any(v4_count(data, c) >= MIN_SANE_V4 for c in clean_cc + [t['cc'] for t in clean_t]):
        raise ValueError('開放的國家 IP 資料量過少，為避免把所有人擋在外面，拒絕套用')
    return {'enabled': enabled, 'countries': clean_cc, 'temporary': clean_t}


def effective_countries(policy):
    cc = list(policy.get('countries', []))
    for t in policy.get('temporary', []):
        if int(t.get('until', 0)) > now() and t['cc'] not in cc:
            cc.append(t['cc'])
    return cc


# ---------------------------------------------------------------- nftables
def nft(args, stdin=None):
    return subprocess.run(['nft'] + args, input=stdin, capture_output=True, text=True)


def collapse(nets, version):
    objs = [ipaddress.ip_network(n) for n in nets]
    objs = [o for o in objs if o.version == version]
    return [str(o) for o in ipaddress.collapse_addresses(objs)]


def build_ruleset(policy, data):
    ccs = effective_countries(policy)
    v4 = list(ALWAYS_ALLOW_V4)
    v6 = list(ALWAYS_ALLOW_V6)
    for c in ccs:
        v4 += data.get(c, {}).get('v4', [])
        v6 += data.get(c, {}).get('v6', [])
    v4 = collapse(v4, 4)
    v6 = collapse(v6, 6)
    ports = ', '.join(str(p) for p in sorted(PROTECTED_PORTS))
    # Matching on the ORIGINAL destination port (pre-DNAT) means the rule sees 443/993
    # even after Docker has rewritten the packet towards a container. Only NEW
    # connections are checked, so changing the sets never cuts an open session, and
    # anything that is not a protected port (25, 80, ssh, ...) is never looked at.
    rules = f"""table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  set allow4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {', '.join(v4)} }} }}
  set allow6 {{ type ipv6_addr; flags interval; auto-merge; elements = {{ {', '.join(v6)} }} }}
  counter passed {{ }}
  counter dropped {{ }}
  chain geo_check {{
    ip saddr @allow4 counter name passed accept
    ip6 saddr @allow6 counter name passed accept
    limit rate 20/minute burst 40 packets log prefix "{LOG_PREFIX}" level info
    counter name dropped drop
  }}
  chain geo_forward {{
    type filter hook forward priority -5; policy accept;
    ct state new meta l4proto tcp ct original proto-dst {{ {ports} }} jump geo_check
  }}
  chain geo_input {{
    type filter hook input priority -5; policy accept;
    ct state new meta l4proto tcp th dport {{ {ports} }} jump geo_check
  }}
}}
"""
    return rules, ccs, len(v4), len(v6)


def apply_ruleset(rules):
    with tempfile.NamedTemporaryFile('w', suffix='.nft', delete=False) as fh:
        fh.write(rules)
        path = fh.name
    try:
        chk = nft(['-c', '-f', path])
        if chk.returncode != 0:
            raise RuntimeError('防火牆規則檢查失敗：' + chk.stderr.strip()[:300])
        res = nft(['-f', path])
        if res.returncode != 0:
            raise RuntimeError('防火牆規則套用失敗：' + res.stderr.strip()[:300])
    finally:
        os.unlink(path)


def remove_table():
    if nft(['list', 'table', 'inet', TABLE]).returncode == 0:
        nft(['delete', 'table', 'inet', TABLE])


def counters():
    out = {}
    for name in ('passed', 'dropped'):
        r = nft(['-j', 'list', 'counter', 'inet', TABLE, name])
        try:
            for item in json.loads(r.stdout).get('nftables', []):
                if 'counter' in item:
                    out[name] = item['counter'].get('packets', 0)
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- status
def lookup_table(data):
    starts, rows = [], []
    for cc, d in data.items():
        for c in d.get('v4', []):
            n = ipaddress.IPv4Network(c)
            rows.append((int(n.network_address), int(n.broadcast_address), cc))
    rows.sort()
    starts = [r[0] for r in rows]
    return starts, rows


def country_of(ip, table):
    starts, rows = table
    try:
        a = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return '??'
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and rows[i][0] <= a <= rows[i][1]:
        return rows[i][2]
    return '??'


def recent_blocks(data):
    """Summarise the last 24 h of drops from the kernel log (rate-limited samples)."""
    r = subprocess.run(['journalctl', '-k', '--since', '-24h', '--no-pager', '-o', 'short-unix',
                        '--grep', LOG_PREFIX.strip()], capture_output=True, text=True)
    per_ip = {}
    for line in r.stdout.splitlines():
        m_src = re.search(r'SRC=([0-9a-fA-F.:]+)', line)
        m_dpt = re.search(r'DPT=(\d+)', line)
        if not m_src:
            continue
        ts = int(float(line.split(' ', 1)[0])) if line[:1].isdigit() else 0
        ip = m_src.group(1)
        e = per_ip.setdefault(ip, {'ip': ip, 'count': 0, 'last': 0, 'ports': set()})
        e['count'] += 1
        e['last'] = max(e['last'], ts)
        if m_dpt:
            e['ports'].add(int(m_dpt.group(1)))
    table = lookup_table(data) if per_ip else None
    rows = sorted(per_ip.values(), key=lambda e: -e['count'])[:30]
    for e in rows:
        e['cc'] = country_of(e['ip'], table)
        e['ports'] = sorted(e['ports'])
    by_cc = {}
    for e in per_ip.values():
        cc = country_of(e['ip'], table) if table else '??'
        by_cc[cc] = by_cc.get(cc, 0) + e['count']
    return rows, dict(sorted(by_cc.items(), key=lambda kv: -kv[1])[:15])


def write_status(state, message, policy=None, data=None, extra=None):
    st = read_json(STATUS, {})
    st.update({'state': state, 'message': message, 'updated': now(),
               'ports': [{'port': p, 'name': n} for p, n in sorted(PROTECTED_PORTS.items())],
               'open_ports': [{'port': 25, 'name': 'SMTP 收信（廠商寄信）'},
                              {'port': 80, 'name': 'HTTP（導向 https、憑證驗證）'}]})
    if policy is not None:
        st['policy'] = {'enabled': policy.get('enabled', False),
                        'countries': policy.get('countries', []),
                        'temporary': policy.get('temporary', []),
                        'changed': policy.get('changed'), 'by': policy.get('by')}
    if data is not None:
        st['available_countries'] = sorted(data.keys())
    if extra:
        st.update(extra)
    os.makedirs(UPDATER_DIR, exist_ok=True)
    atomic_write(STATUS, st)


def enforce(policy, reason):
    data, fetched = load_data()
    active = nft(['list', 'table', 'inet', TABLE]).returncode == 0
    if not data:
        write_status('error', '尚未下載國家 IP 資料（每天自動更新；也可在主機執行 --refresh-data）',
                     policy, None, {'active': active, 'data_fetched': None})
        return False
    # expired temporary entries fall off here
    policy['temporary'] = [t for t in policy.get('temporary', []) if int(t.get('until', 0)) > now()]
    if not policy.get('enabled'):
        remove_table()
        write_status('disabled', '登入地區限制未啟用：所有國家都可以連線登入', policy, data,
                     {'active': False, 'data_fetched': fetched, 'effective': [], 'set_v4': 0})
        return True
    try:
        clean = validate_policy(policy, data)
    except ValueError as e:
        write_status('error', f'目前設定無法套用（{e}），防火牆維持原狀', policy, data,
                     {'active': active, 'data_fetched': fetched})
        return False
    policy.update(clean)
    rules, ccs, n4, n6 = build_ruleset(policy, data)
    apply_ruleset(rules)
    rows, by_cc = recent_blocks(data)
    write_status('enforcing', f'已啟用：只有 {"、".join(ccs)} 的連線可以登入（{reason}）', policy, data,
                 {'active': True, 'data_fetched': fetched, 'effective': ccs, 'set_v4': n4,
                  'set_v6': n6, 'counters': counters(), 'blocked_recent': rows,
                  'blocked_by_country': by_cc, 'applied': now()})
    return True


# ---------------------------------------------------------------- web request
def verify_passphrase(pw):
    try:
        salt, want = open(SECRET_FILE, encoding='ascii').read().strip().split(':', 1)
    except Exception:
        raise ValueError('尚未設定更新密碼')
    got = hashlib.sha256((salt + pw).encode('utf-8')).hexdigest()
    return hmac.compare_digest(got, want)


def handle_request():
    if not os.path.isfile(REQUEST):
        return 0
    try:
        with open(REQUEST, encoding='utf-8') as fh:
            req = json.loads(fh.read(65536))
    except Exception:
        req = None
    finally:
        try:
            os.unlink(REQUEST)
        except FileNotFoundError:
            pass
    policy = read_json(POLICY, empty_policy())
    if not isinstance(req, dict):
        write_status('rejected', '請求格式不正確', policy)
        return 1
    user = re.sub(r'[^A-Za-z0-9@._-]', '_', str(req.get('user', '?')))[:64]
    try:
        ts = int(req.get('ts', 0))
    except (TypeError, ValueError):
        ts = 0
    age = now() - ts
    if ts == 0 or age > MAX_AGE or age < -60:
        write_status('rejected', '請求已逾時，請重新操作', policy)
        log(f'rejected stale request from {user}')
        return 1
    try:
        ok = verify_passphrase(str(req.get('passphrase', '')))
    except ValueError as e:
        write_status('rejected', str(e), policy)
        return 1
    if not ok:
        write_status('rejected', '更新密碼不正確', policy)
        log(f'FAILED passphrase from {user}')
        time.sleep(3)
        return 1
    data, _ = load_data()
    if not data:
        write_status('error', '尚未下載國家 IP 資料，請稍後再試', policy)
        return 1
    try:
        clean = validate_policy(req.get('policy'), data)
    except ValueError as e:
        write_status('rejected', str(e), policy)
        return 1
    clean.update({'changed': now(), 'by': user})
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    atomic_write(POLICY, clean, mode=0o600)
    log(f'policy changed by {user}: enabled={clean["enabled"]} countries={clean["countries"]} '
        f'temporary={[(t["cc"], t["until"]) for t in clean["temporary"]]}')
    return 0 if enforce(clean, f'{user} 於 {time.strftime("%m/%d %H:%M")} 更新') else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--request', action='store_true')
    g.add_argument('--apply', action='store_true')
    g.add_argument('--refresh-data', action='store_true')
    g.add_argument('--disable', action='store_true')
    a = ap.parse_args()
    if os.geteuid() != 0:
        print('請以 root 執行', file=sys.stderr)
        return 1
    try:
        if a.request:
            return handle_request()
        if a.refresh_data:
            n = refresh_data()
            log(f'country data refreshed: {n} countries')
            print(f'已更新 {n} 個國家的 IP 資料')
            return 0 if enforce(read_json(POLICY, empty_policy()), '每日資料更新') else 1
        if a.disable:
            p = read_json(POLICY, empty_policy())
            p.update({'enabled': False, 'changed': now(), 'by': 'host (--disable)'})
            os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
            atomic_write(POLICY, p, mode=0o600)
            remove_table()
            write_status('disabled', '已在主機上緊急停用登入地區限制', p, load_data()[0] or None,
                         {'active': False})
            log('disabled from the host')
            print('已停用登入地區限制，所有國家都可以連線登入。')
            return 0
        return 0 if enforce(read_json(POLICY, empty_policy()), '定期檢查') else 1
    except Exception as e:  # never leave the page without an explanation
        write_status('error', f'執行失敗：{e}', read_json(POLICY, empty_policy()))
        log(f'error: {e}')
        print(f'錯誤：{e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

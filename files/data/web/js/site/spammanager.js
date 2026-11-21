(function ($) {
  'use strict';
  var api = '/admin/SpamManagerApi', busy = false;
  var SM = window.SpamManager = {state: null};
  function el(id) { return document.getElementById(id); }
  function node(tag, text, cls) { var n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
  function message(text, danger) { var n = el('sm-notice'); if (!n) return; n.textContent = text; n.className = 'small mb-2 ' + (danger ? 'text-danger' : 'text-success'); }
  function syncToken(data) {
    if (!data || !data.csrf_token) return;
    var token = el('spammanager-csrf'); if (token) token.value = data.csrf_token;
    document.querySelectorAll('input[name="csrf_token"]').forEach(function (n) { n.value = data.csrf_token; });
  }
  SM.request = function (operation, payload) {
    if (busy) return $.Deferred().reject({responseJSON: {message: '另一筆設定正在儲存，請稍候。'}}, 'busy').promise();
    busy = true;
    var req = $.ajax({url: api, type: 'POST', dataType: 'json', timeout: 45000, data: {op: operation, payload: JSON.stringify(payload), csrf_token: el('spammanager-csrf').value}});
    req.done(syncToken).fail(function (xhr) { syncToken(xhr.responseJSON); }).always(function () { busy = false; });
    return req;
  };
  function failure(xhr, status) {
    message(status === 'timeout' ? '等待伺服器回應逾時。請重新讀取設定確認結果，避免重複送出。' : ((xhr.responseJSON || {}).message || '讀取或儲存失敗，請確認登入狀態。'), true);
  }
  function save(op, data, button, done) {
    if (button) button.disabled = true;
    message('正在儲存並核對設定…', false);
    return SM.request(op, data).done(function (r) { message(r.message || '已儲存。', false); if (done) done(r.data); }).fail(failure).always(function () { if (button) button.disabled = false; });
  }
  var page = 0, selected = {}, drafts = {}, mapFile = '', historyRows = [], historyLoaded = false, rejectedRows = [], rejectedLoaded = false, outboundRows = [], outboundLoaded = false;
  var actionLabels = {'no action':'正常投遞', 'add header':'垃圾標記', 'greylist':'灰名單', 'soft reject':'暫時拒收', 'reject':'拒收', 'rewrite subject':'改寫主旨'};
  var symbolNames = {'R_SPF_FAIL':'SPF 驗證失敗', 'R_DKIM_REJECT':'DKIM 驗證失敗', 'BAYES_SPAM':'貝氏分類：垃圾郵件', 'BAYES_HAM':'貝氏分類：正常郵件', 'CLAM_VIRUS':'病毒掃描命中', 'DMARC_POLICY_REJECT':'DMARC 拒收政策', 'FUZZY_DENIED':'模糊指紋命中', 'R_DKIM_ALLOW':'DKIM 驗證成功', 'R_SPF_ALLOW':'SPF 驗證成功'};
  var descriptionTranslations = window.SpamManagerDescriptions || {};
  function symbolDescription(description) {
    if (Object.prototype.hasOwnProperty.call(descriptionTranslations, description)) return descriptionTranslations[description];
    var heinlein = /^Heinlein Support Spamschutz (Body|Header)-(\d+)(?:\s+(.+))?$/.exec(description || '');
    if (heinlein) {
      var category = heinlein[3] || '';
      var labels = {Spam:'垃圾郵件',SPAM:'垃圾郵件',Phishing:'網路釣魚',Pishing:'網路釣魚',Malware:'惡意軟體',Virus:'病毒',Rechnungsvirus:'帳單病毒'};
      var label = labels[category];
      var special = /^Header-Spamschutzregel\s+(\d+)$/.exec(category);
      var jpberlin = /^JPBERLIN-(\d+)$/.exec(category);
      var nazi = /^Nazi Spam(\d+)$/.exec(category);
      if (special) label = '標頭垃圾郵件規則 ' + special[1];
      else if (jpberlin) label = 'JPBERLIN 規則 ' + jpberlin[1];
      else if (nazi) label = '垃圾郵件規則 ' + nazi[1];
      return 'Heinlein 垃圾郵件過濾：' + (heinlein[1] === 'Header' ? '標頭' : '內文') + '規則 ' + heinlein[2] + (label ? '（分類：' + label + '）' : '');
    }
    return description ? '自訂評分規則（請依規則代碼查閱原始說明）' : '此評分項目沒有提供說明';
  }
  function openPanel(key) {
    if (!document.querySelector('[data-sm-section="' + key + '"]')) key = 'overview';
    document.querySelectorAll('[data-sm-section]').forEach(function (n) { n.hidden = n.getAttribute('data-sm-section') !== key; });
    document.querySelectorAll('[data-sm-panel]').forEach(function (n) { var active = n.getAttribute('data-sm-panel') === key; n.classList.toggle('btn-primary', active); n.classList.toggle('btn-outline-secondary', !active); n.setAttribute('aria-pressed', active ? 'true' : 'false'); });
    window.history.replaceState(null, '', '#sm-' + key);
    if (key === 'history' && !historyLoaded) loadHistory();
    if (key === 'rejected' && !rejectedLoaded) loadRejected();
    if (key === 'outbound' && !outboundLoaded) loadOutbound();
  }
  function summary() {
    var s = SM.state; if (!s) return;
    var host = el('sm-summary'); host.replaceChildren();
    var counts = [['掃描總數', s.stats ? s.stats.scanned : '—'], ['評分項目', s.symbols.length], ['全域名單項目', Object.values(s.maps).filter(function (m) { return m.global; }).reduce(function (n, m) { return n + m.count; }, 0)], ['個別設定', s.policies.length], ['防冒名啟用', s.rules.filter(function (r) { return r.model && r.active; }).length]];
    counts.forEach(function (v) { host.appendChild(node('span', v[0] + '：' + v[1])); });
    el('sm-threshold-summary').textContent = s.actions ? ('灰名單 ' + s.actions.greylist + ' ／ 垃圾標記 ' + s.actions['add header'] + ' ／ 拒收 ' + s.actions.reject) : 'Rspamd 暫時無法讀取';
    var related = s.rules.filter(function (r) { return r.model && r.active; }).map(function (r) { return r.model.name + ' → 允許 ' + r.model.emails.join('、'); });
    el('sm-relations').textContent = '防冒名關聯：' + (related.join('；') || '尚無啟用規則') + '。防冒名命中時會使用其專屬動作門檻，一般總分門檻不直接套用。';
    var audit = el('sm-audit'); audit.replaceChildren();
    if (!s.audit.length) audit.textContent = '尚無操作紀錄。每次調整前會保留設定備份。';
    var operationNames = {save_actions:'全域門檻',save_symbols:'評分權重',save_map:'全域名單',policy_add:'新增個別名單',policy_delete:'移除個別名單',scope_score:'個別門檻',impersonation_save:'防冒名儲存',impersonation_delete:'防冒名刪除',release:'放行被拒郵件',outbound_release:'放行外寄郵件',outbound_delete:'刪除外寄攔截'};
    s.audit.forEach(function (v) { audit.appendChild(node('div', v.time + ' · ' + v.actor + ' · ' + (operationNames[v.operation] || v.operation))); });
  }
  function actions() {
    var a = SM.state.actions;
    if (a) { el('sm-grey').value = a.greylist; el('sm-tag').value = a['add header']; el('sm-reject').value = a.reject; }
    el('sm-actions-form').querySelector('button').disabled = !a;
    simulate();
  }
  function filteredSymbols() {
    var term = el('sm-symbol-search').value.toLowerCase().trim();
    return SM.state.symbols.filter(function (s) { return (s.name + ' ' + s.group + ' ' + s.description + ' ' + symbolDescription(s.description) + ' ' + (symbolNames[s.name] || '')).toLowerCase().indexOf(term) >= 0; });
  }
  function symbols() {
    if (!SM.state) return;
    var rows = filteredSymbols(), total = Math.max(1, Math.ceil(rows.length / 50)); page = Math.max(0, Math.min(page, total - 1));
    var tbody = el('sm-symbol-rows'); tbody.replaceChildren();
    rows.slice(page * 50, page * 50 + 50).forEach(function (s) {
      var tr = node('tr'), td = node('td'), checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.checked = !!selected[s.name]; checkbox.setAttribute('aria-label', '試算 ' + s.name);
      checkbox.addEventListener('change', function () { if (checkbox.checked) selected[s.name] = true; else delete selected[s.name]; simulate(); }); td.appendChild(checkbox); tr.appendChild(td);
      td = node('td'); td.appendChild(node('div', s.name, 'font-monospace small')); td.appendChild(node('small', s.group, 'text-muted')); tr.appendChild(td);
      td = node('td', symbolNames[s.name] || symbolDescription(s.description), 'small'); td.title = s.description || ''; tr.appendChild(td);
      td = node('td'); var input = node('input'); input.type = 'number'; input.step = 'any'; input.min = '-10000'; input.max = '10000'; input.className = 'form-control form-control-sm'; input.value = Object.prototype.hasOwnProperty.call(drafts, s.name) ? drafts[s.name] : s.weight; input.setAttribute('aria-label', s.name + ' 分數');
      if (Object.prototype.hasOwnProperty.call(drafts, s.name)) input.classList.add('border-warning');
      input.addEventListener('input', function () { if (input.value !== '' && Number(input.value) === s.weight) delete drafts[s.name]; else drafts[s.name] = input.value; input.classList.toggle('border-warning', Object.prototype.hasOwnProperty.call(drafts, s.name)); updateDraftButton(); simulate(); }); td.appendChild(input); tr.appendChild(td); tbody.appendChild(tr);
    });
    if (!rows.length) { var tr = node('tr'), td = node('td', '沒有符合的評分項目。'); td.colSpan = 4; tr.appendChild(td); tbody.appendChild(tr); }
    el('sm-symbol-page').textContent = rows.length + ' 項 · 第 ' + (page + 1) + ' / ' + total + ' 頁（每頁 50 項）';
    el('sm-symbol-prev').disabled = page === 0; el('sm-symbol-next').disabled = page >= total - 1; updateDraftButton();
  }
  function updateDraftButton() { var count = Object.keys(drafts).length; el('sm-save-symbols').disabled = !count; el('sm-save-symbols').textContent = count ? '儲存 ' + count + ' 項權重' : '儲存權重'; }
  function simulate() {
    if (!SM.state) return;
    var total = 0, names = Object.keys(selected);
    names.forEach(function (name) { var s = SM.state.symbols.find(function (v) { return v.name === name; }); if (s) total += Number(Object.prototype.hasOwnProperty.call(drafts, name) ? drafts[name] : s.weight); });
    var grey = Number(el('sm-grey').value), tag = Number(el('sm-tag').value), reject = Number(el('sm-reject').value);
    var action = total >= reject ? '達拒收門檻' : total >= tag ? '達垃圾標記門檻' : total >= grey ? '達灰名單門檻' : '未達一般過濾門檻';
    el('sm-simulation').textContent = names.length ? names.length + ' 項合計 ' + total.toFixed(2) + ' 分 → ' + action + (Object.keys(drafts).length ? '（含未儲存權重）' : '') : '勾選項目試算總分；也可從郵件紀錄帶入命中項目。';
  }
  var MAP_CONDITIONS = {
    address: [{v:'addr',t:'精確地址',p:'例如 sender@example.com'},{v:'domain',t:'整個網域',p:'例如 example.com'},{v:'subdomain',t:'網域含子網域',p:'例如 example.com'},{v:'local',t:'寄件者帳號',p:'例如 newsletter'}],
    host: [{v:'host',t:'精確主機名',p:'例如 mta.example.com'},{v:'hostsuffix',t:'主機名尾碼（含子網域）',p:'例如 example.com'}],
    ip: [{v:'ip',t:'單一 IP 位址',p:'例如 203.0.113.7'},{v:'cidr',t:'網段（CIDR）',p:'例如 203.0.113.0/24'}],
    asn: [{v:'asn',t:'ASN（用規則預設分數）',p:'例如 12874'},{v:'asnscore',t:'ASN + 分數倍數',p:'例如 12874 2'}]
  };
  var MAP_HINTS = {
    address: '一行一個正規表示式；# 開頭為註解。比對郵件地址，不比對來源 IP 或主機名。',
    host: '一行一個正規表示式；# 開頭為註解。比對主機名稱字串，不比對郵件地址。',
    ip: '一行一個 IP 位址或 CIDR 網段；# 開頭為註解。此名單不接受正規表示式。',
    asn: '一行一個 ASN；第二欄是「倍數」而非絕對分數 —— 規則預設 5 分，寫 2 代表 10 分。# 開頭為註解，此名單不接受正規表示式。'
  };
  function mapEffect(file) {
    if (file.indexOf('global_rcpt_white') === 0) return '比對收件地址，命中時可直接接受，會影響後續評分結果。';
    if (file.indexOf('global_rcpt_black') === 0) return '比對收件地址，命中時可直接拒收。';
    if (file.indexOf('helo') >= 0) return '比對寄件伺服器自稱的 HELO／EHLO 名稱；命中時' + (file.indexOf('white') >= 0 ? '減 2050 分。' : '加 2050 分。') + 'HELO 可被偽造，請搭配其他條件使用。';
    if (file.indexOf('hostname') >= 0) return '比對來源 IP 的反解（PTR）名稱；命中時' + (file.indexOf('white') >= 0 ? '減 2050 分。' : '加 2050 分。') + '沒有反解紀錄的來源不會命中。';
    if (file === 'ip_wl.map') return '比對連線來源 IP 或網段；命中時減 2050 分，等同強制放行。請只填信任的中繼主機。';
    if (file === 'global_ip_blacklist.map') return '比對連線來源 IP 或網段；命中時加 2050 分，等同強制拒收。';
    if (file === 'bad_asn.map') return '比對來源 IP 所屬的 ASN（整個 ISP）；規則預設每筆 5 分，第二欄是倍數（寫 2 即 10 分）。整個 ISP 範圍很廣，請謹慎。白名單寄件者會略過此規則（已實測）。';
    if (file.indexOf('global_') === 0) return '比對' + (file.indexOf('mime') >= 0 ? '郵件 From 地址' : 'SMTP 信封寄件地址') + '；命中時' + (file.indexOf('white') >= 0 ? '減 2050 分。' : '加 2050 分。') + '其他規則仍可能改變最終動作。';
    return '此為 Mailcow 原有內容／來源名單，實際加減分取決於相應評分項目。';
  }
  function loadMapOptions() {
    var select = el('sm-map-select'), current = select.value; select.replaceChildren();
    Object.values(SM.state.maps).forEach(function (m) { var o = node('option', m.label + '（' + m.count + '）'); o.value = m.file; select.appendChild(o); });
    if (SM.state.maps[current]) select.value = current; showMap();
  }
  function showMap() {
    mapFile = el('sm-map-select').value; var m = SM.state.maps[mapFile]; if (!m) return;
    el('sm-map-content').value = m.content; el('sm-map-effect').textContent = mapEffect(mapFile); el('sm-map-form').querySelector('button[type=submit]').disabled = false;
    mapConditions(m); mapCount();
  }
  // Which conditions make sense depends on what the map matches: an address map takes
  // an address or a domain, a HELO/rDNS map takes a host name, an IP map takes an
  // address or CIDR, and bad_asn.map takes an ASN with an optional score.
  function mapFamily(m) {
    if (m.kind === 'ip') return 'ip';
    if (m.kind === 'asn') return 'asn';
    return (m.file.indexOf('helo') >= 0 || m.file.indexOf('hostname') >= 0) ? 'host' : 'address';
  }
  function mapConditions(m) {
    var select = el('sm-map-kind'), list = MAP_CONDITIONS[mapFamily(m)];
    select.replaceChildren();
    list.forEach(function (c) { var o = node('option', c.t); o.value = c.v; select.appendChild(o); });
    select.value = list[0].v; el('sm-map-address').placeholder = list[0].p;
    el('sm-map-hint').textContent = MAP_HINTS[mapFamily(m)];
  }
  function mapCount() {
    var lines = el('sm-map-content').value.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) { return l && l.charAt(0) !== '#'; });
    el('sm-map-count').textContent = lines.length + ' 筆條件';
    var pair = mapFile.indexOf('blacklist') >= 0 ? mapFile.replace('blacklist', 'whitelist') : mapFile.replace('whitelist', 'blacklist');
    var opposite = SM.state && SM.state.maps[pair];
    var conflicts = opposite && pair !== mapFile ? lines.filter(function (l) { return opposite.content.split(/\r?\n/).some(function (v) { return v.trim() === l; }); }) : [];
    el('sm-map-conflicts').textContent = conflicts.length ? '黑白名單有 ' + conflicts.length + ' 筆完全相同條件，請先確認想要的處理方式。' : '';
  }
  function scopeRows() { var target = el('sm-scope').value.trim(); return SM.state.policies.filter(function (v) { return v.object === target && ['lowspamlevel','highspamlevel'].indexOf(v.option) >= 0; }); }
  function scope() {
    if (!SM.state) return; var rows = scopeRows(), a = SM.state.actions || {};
    var low = rows.find(function (v) { return v.option === 'lowspamlevel'; }), high = rows.find(function (v) { return v.option === 'highspamlevel'; });
    el('sm-scope-tag').value = low ? low.value : a['add header']; el('sm-scope-reject').value = high ? high.value : a.reject;
    el('sm-scope-note').textContent = rows.length ? '目前使用專屬門檻；灰名單門檻由垃圾標記門檻減 1。防冒名等更高優先規則仍可能覆寫。' : '目前繼承全域門檻。可為此信箱或網域另設門檻；寄件者白名單與防冒名為不同規則層級。';
  }
  function policies() {
    var list = el('sm-scope-targets'); list.replaceChildren(); SM.state.targets.forEach(function (v) { var o = node('option'); o.value = v; list.appendChild(o); });
    var tbody = el('sm-policy-rows'); tbody.replaceChildren(); var labels = {whitelist_from:'寄件者白名單', blacklist_from:'寄件者黑名單', lowspamlevel:'垃圾標記門檻', highspamlevel:'拒收門檻'};
    SM.state.policies.forEach(function (p) { var tr = node('tr'); tr.appendChild(node('td', p.object, 'small')); tr.appendChild(node('td', labels[p.option], 'small')); tr.appendChild(node('td', p.value, 'small')); var td = node('td');
      var edit = node('button','選取','btn btn-sm btn-outline-secondary'); edit.type='button'; edit.addEventListener('click',function(){el('sm-scope').value=p.object;scope();});td.appendChild(edit);
      if (p.option === 'whitelist_from' || p.option === 'blacklist_from') { var del = node('button', '移除', 'btn btn-sm btn-outline-danger ms-1'); del.type = 'button'; del.addEventListener('click',function(){if(window.confirm('移除 ' + p.object + ' 的 ' + p.value + ' 名單項目？')) save('policy_delete',{id:p.prefid,baseline:p.hash},del,refreshPolicies);});td.appendChild(del); }
      tr.appendChild(td);tbody.appendChild(tr);
    }); scope();
  }
  function refreshPolicies() { $.getJSON(api, {op:'state'}).done(function(r){SM.state.policies=r.data.policies;SM.state.targets=r.data.targets;SM.state.scope_baselines=r.data.scope_baselines;SM.state.audit=r.data.audit;policies();summary();}).fail(failure); }
  SM.refreshRules = function (rules, preferred) {
    if (SM.state) {SM.state.rules=rules;summary();}
    var select=el('impersonation-rule'), chosen=preferred===undefined?select.value:String(preferred);select.replaceChildren();var empty=node('option','新增防冒名規則');empty.value='';select.appendChild(empty);
    var tbody=el('sm-impersonation-rows');tbody.replaceChildren();
    rules.filter(function(r){return r.model;}).forEach(function(r){
      var o=node('option',r.description);o.value=r.id;o.setAttribute('data-name',r.model.name);o.setAttribute('data-emails',r.model.emails.join('\n'));o.setAttribute('data-active',r.active?'1':'0');o.setAttribute('data-hash',r.hash);select.appendChild(o);
      var tr=node('tr');tr.setAttribute('data-sm-row',r.id);tr.appendChild(node('td',r.model.name));tr.appendChild(node('td',r.model.emails.join('、'),'small'));var td=node('td');td.appendChild(node('span',r.active?'啟用':'停用','badge '+(r.active?'bg-success':'bg-secondary')));tr.appendChild(td);td=node('td');var b=node('button','編輯','btn btn-sm btn-outline-secondary');b.type='button';b.setAttribute('data-sm-rule',r.id);td.appendChild(b);tr.appendChild(td);tbody.appendChild(tr);
    });
    if(!tbody.children.length){var tr=node('tr'),td=node('td','尚無防冒名規則。');td.colSpan=4;tr.appendChild(td);tbody.appendChild(tr);}
    select.value=chosen;if(select.selectedIndex<0)select.value='';if(SM.onRulesChange)SM.onRulesChange();
  };
  function historyDetail(row) {
    var host=el('sm-history-detail');host.replaceChildren();host.appendChild(node('h3','命中項目與調整','h6'));
    var limits=row.thresholds || {};host.appendChild(node('p','當時總分 '+row.score+'；當時門檻：'+Object.keys(limits).map(function(k){return (actionLabels[k]||k)+' '+limits[k];}).join(' / ')+'。以下各項分數可能包含動態權重，未必等於目前設定值。','text-muted'));
    var table=node('table',undefined,'table table-sm sm-table'),body=node('tbody');
    Object.entries(row.symbols || {}).sort(function(a,b){return Math.abs(b[1].score)-Math.abs(a[1].score);}).forEach(function(v){var tr=node('tr');tr.appendChild(node('td',v[0],'font-monospace'));tr.appendChild(node('td',String(v[1].score)));var desc=node('td',symbolNames[v[0]]||symbolDescription(v[1].description),'small');desc.title=v[1].description||'';tr.appendChild(desc);var td=node('td'),b=node('button','調整權重','btn btn-sm btn-outline-secondary');b.type='button';b.disabled=!SM.state || !SM.state.symbols.some(function(s){return s.name===v[0];});b.addEventListener('click',function(){openPanel('scores');el('sm-symbol-search').value=v[0];page=0;symbols();});td.appendChild(b);tr.appendChild(td);body.appendChild(tr);});table.appendChild(body);host.appendChild(table);
    var test=node('button','帶入這封郵件的項目試算','btn btn-sm btn-outline-primary');test.type='button';test.addEventListener('click',function(){selected={};Object.keys(row.symbols||{}).forEach(function(k){selected[k]=true;});el('sm-symbol-search').value='';page=0;symbols();simulate();openPanel('scores');});host.appendChild(test);
  }
  function renderHistory() {
    var term=el('sm-history-search').value.toLowerCase(),tbody=el('sm-history-rows');tbody.replaceChildren();
    historyRows.filter(function(r){return [r.sender_mime,r.sender_smtp,r.subject,(r.rcpt_mime||[]).join(' ')].join(' ').toLowerCase().indexOf(term)>=0;}).forEach(function(r){var tr=node('tr'),stamp=r.unix_time||r.timestamp||r.time;tr.appendChild(node('td',stamp?new Date(Number(stamp)*1000).toLocaleString('zh-TW',{hour12:false}):'—','small'));var td=node('td');td.appendChild(node('div',r.sender_mime||r.sender_smtp||'','small'));var subject=node('div',r.subject||'（無主旨）','small text-muted sm-subject');subject.title=r.subject||'';td.appendChild(subject);tr.appendChild(td);tr.appendChild(node('td',Number(r.score).toFixed(2)));tr.appendChild(node('td',actionLabels[r.action]||r.action,'small'));td=node('td');var b=node('button','查看','btn btn-sm btn-outline-secondary');b.type='button';b.addEventListener('click',function(){historyDetail(r);});td.appendChild(b);tr.appendChild(td);tbody.appendChild(tr);});
  }
  function loadHistory() {
    el('sm-history-status').textContent='正在讀取 Rspamd 掃描紀錄…';
    $.ajax({url:api,type:'GET',dataType:'json',timeout:20000,data:{op:'history'}}).done(function(r){historyLoaded=true;historyRows=r.data.rows;el('sm-history-status').textContent='共 '+historyRows.length+' 筆。此處是掃描歷史；SMTP 連線階段拒收及未記錄的郵件不會出現在此。';renderHistory();}).fail(function(xhr,status){el('sm-history-status').textContent='紀錄讀取失敗，可按更新重試。';failure(xhr,status);});
  }
  // The quarantine table holds reject, add header and rewrite subject mail, so the
  // tab filters by action. Only reject items get a release button: an 'add header'
  // message was already delivered to the mailbox, so there is nothing to release.
  var REJECTED_ACTION_LABELS={'reject':'拒收','add header':'加標記','rewrite subject':'改寫主旨','soft reject':'暫時拒收','greylist':'暫時延遲','no action':'正常投遞'};
  // Actions where the message reached the inbox untouched: nothing to release and
  // nothing to copy, the row exists only so an admin can read what was delivered.
  var REJECTED_PASSIVE_ACTIONS={'no action':1,'greylist':1,'soft reject':1};
  function rejectedPassive(a){return !!REJECTED_PASSIVE_ACTIONS[a||''];}
  function rejectedFilter(){var v=el('sm-rejected-action');return v?v.value:'all';}
  function rejectedVisible(){
    var want=rejectedFilter();
    return want==='all'?rejectedRows:rejectedRows.filter(function(r){return (r.action||'')===want;});
  }
  function rejectedStatus(){
    var total=rejectedRows.length,shown=rejectedVisible().length;
    var counts={};rejectedRows.forEach(function(r){var a=r.action||'（未知）';counts[a]=(counts[a]||0)+1;});
    var breakdown=Object.keys(counts).sort().map(function(a){return (REJECTED_ACTION_LABELS[a]||a)+' '+counts[a];}).join('、');
    el('sm-rejected-status').textContent='留存紀錄共 '+total+' 封'+(breakdown?('（'+breakdown+'）'):'')+'，目前顯示 '+shown+' 封。涵蓋所有收件人為本機信箱的外部來信，不論是否被攔截；SMTP 連線階段拒收與往外寄被拒不會出現在此。';
  }
  function renderRejected(){
    var term=el('sm-rejected-search').value.toLowerCase(),tbody=el('sm-rejected-rows');tbody.replaceChildren();
    var pool=rejectedVisible();
    var rows=pool.filter(function(r){return [r.sender,r.rcpt,r.subject].join(' ').toLowerCase().indexOf(term)>=0;});
    if(!rows.length){var tr=node('tr'),td=node('td',pool.length?'沒有符合搜尋的郵件。':(rejectedRows.length?'這個動作沒有留存的郵件，可改選「全部」。':'目前沒有被留存的郵件。'));td.colSpan=5;td.className='small text-muted';tr.appendChild(td);tbody.appendChild(tr);return;}
    rows.forEach(function(r){
      var tr=node('tr'),action=r.action||'';
      tr.appendChild(node('td',r.created?new Date(r.created*1000).toLocaleString('zh-TW',{hour12:false}):'—','small'));
      var actTd=node('td',REJECTED_ACTION_LABELS[action]||action||'—','small '+(action==='reject'?'text-danger':(action==='add header'?'sm-act-tagged':(rejectedPassive(action)?'text-muted':'text-warning'))));
      if(action==='add header'){actTd.style.setProperty('color','#0d6efd','important');actTd.style.setProperty('font-weight','700','important');}
      tr.appendChild(actTd);
      var td=node('td');td.appendChild(node('div',(r.sender||'（空寄件者）')+' → '+(r.rcpt||''),'small'));
      var subject=node('div',r.subject||'（無主旨）','small text-muted sm-subject');subject.title=r.subject||'';td.appendChild(subject);
      if(r.virus){var vb=node('span','病毒命中','badge bg-danger');td.appendChild(vb);}
      tr.appendChild(td);
      tr.appendChild(node('td',Number(r.score).toFixed(2)));
      td=node('td','',' sm-actions');
      var view=node('button','檢視','btn btn-sm btn-outline-secondary me-1');view.type='button';
      view.addEventListener('click',function(){showMessage(r,view);});td.appendChild(view);
      if(action==='reject'){
        var b=node('button','放行','btn btn-sm btn-outline-primary me-1');b.type='button';
        b.addEventListener('click',function(){releaseRejected(r,b);});td.appendChild(b);
      }else if(rejectedPassive(action)){
        // Delivered to the inbox already; only viewing and deleting the copy apply.
      }else{
        // Already delivered to the mailbox's Junk folder, so there is nothing to
        // release -- but a clean copy can still be put in the inbox.
        var c=node('button','複製至收件匣','btn btn-sm btn-outline-primary me-1');c.type='button';
        c.addEventListener('click',function(){copyToInbox(r,c);});td.appendChild(c);
      }
      var lb=node('button','名單','btn btn-sm btn-outline-warning');lb.type='button';
      lb.addEventListener('click',function(){showList(r);});td.appendChild(lb);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }
  // Reuse the native /inc/ajax/qitem_details.php endpoint: it already enforces admin
  // or mailbox-owner access, caps the message at 10 MiB and runs the HTML part through
  // html2text. Every field below is inserted with textContent, so nothing from a held
  // message is ever parsed as markup, and no remote content is fetched.
  var msgModal=null, msgCurrent=null, msgSequence=0;
  function msgSet(id,value){el(id).textContent=(value===undefined||value===null||value==='')?'—':String(value);}
  function showMessage(r,button){
    var sequence=++msgSequence;
    if(!msgModal)msgModal=new bootstrap.Modal(el('sm-msg-modal'));
    msgCurrent=r;
    el('sm-msg-error').hidden=true;
    ['sm-msg-action','sm-msg-envfrom','sm-msg-hfrom','sm-msg-rcpt','sm-msg-subject','sm-msg-symbols','sm-msg-atts','sm-msg-text','sm-msg-html'].forEach(function(id){el(id).textContent='讀取中…';});
    el('sm-msg-note').textContent='';
    var release=el('sm-msg-release'),copy=el('sm-msg-copy');
    release.hidden=(r.action!=='reject');
    copy.hidden=(r.action==='reject'||rejectedPassive(r.action));
    release.disabled=true;copy.disabled=true;
    el('sm-msg-list').disabled=true;
    button.disabled=true;
    msgModal.show();
    $.ajax({url:'/inc/ajax/qitem_details.php',type:'GET',dataType:'json',timeout:30000,data:{id:r.id}})
      .done(function(d){
        if(sequence!==msgSequence)return;
        if(!d||d.error){msgFail(d&&d.error?d.error:'無法讀取郵件內容。');return;}
        msgSet('sm-msg-action',(REJECTED_ACTION_LABELS[d.action]||d.action||'—')+'（'+Number(d.score||r.score).toFixed(2)+' 分）');
        msgSet('sm-msg-envfrom',d.env_from);
        msgSet('sm-msg-hfrom',d.header_from);
        msgSet('sm-msg-rcpt',Array.isArray(d.recipients)?d.recipients.map(function(x){return typeof x==='string'?x:((x.address||'')+(x.type?' ('+String(x.type).toUpperCase()+')':''));}).join(', '):(d.recipients||r.rcpt));
        msgSet('sm-msg-subject',d.subject);
        msgSet('sm-msg-symbols',msgSymbols(d.symbols));
        msgAttachments(d.attachments);
        msgSet('sm-msg-text',d.text_plain);
        msgSet('sm-msg-html',d.text_html);
        if(r.virus)el('sm-msg-note').textContent='⚠ 這封曾命中病毒掃描。';
        release.disabled=(r.action!=='reject');
        copy.disabled=(r.action==='reject');
        el('sm-msg-list').disabled=false;
      })
      .fail(function(xhr,status){if(sequence===msgSequence)msgFail(status==='timeout'?'讀取逾時，郵件可能過大。':'讀取失敗（HTTP '+xhr.status+'）。');})
      .always(function(){button.disabled=false;});
  }
  function msgFail(text){
    var box=el('sm-msg-error');box.textContent=text;box.hidden=false;
    ['sm-msg-action','sm-msg-envfrom','sm-msg-hfrom','sm-msg-rcpt','sm-msg-subject','sm-msg-symbols','sm-msg-atts','sm-msg-text','sm-msg-html'].forEach(function(id){el(id).textContent='—';});
    el('sm-msg-release').disabled=true;el('sm-msg-copy').disabled=true;el('sm-msg-list').disabled=true;
  }
  function msgSymbols(symbols){
    if(!symbols)return '';
    var list=Array.isArray(symbols)?symbols:Object.keys(symbols).map(function(k){var v=symbols[k];return {name:(v&&v.name)||k,score:v&&v.score};});
    return list.filter(function(x){return x&&x.name;})
      .sort(function(a,b){return Math.abs(Number(b.score)||0)-Math.abs(Number(a.score)||0);})
      .slice(0,25)
      .map(function(x){return x.name+'('+(Number(x.score)||0).toFixed(2)+')';}).join('、');
  }
  function msgAttachments(atts){
    var host=el('sm-msg-atts');host.replaceChildren();
    if(!atts||!Object.keys(atts).length){host.textContent='—';return;}
    Object.keys(atts).forEach(function(k){
      var v=atts[k],row=node('div','');
      row.appendChild(node('span',(v[0]||'（無檔名）')+'　'+(v[1]||'')+'　'+(v[2]||''),''));
      // Only the native VirusTotal hash lookup is linkable; anything else stays text.
      if(typeof v[3]==='string' && v[3].indexOf('https://www.virustotal.com/')===0){
        var a=node('a','　雜湊查詢','ms-1');a.href=v[3];a.target='_blank';a.rel='noopener noreferrer';row.appendChild(a);
      }
      host.appendChild(row);
    });
  }
  function copyToInbox(r,button){
    if(!window.confirm('把這封「'+(REJECTED_ACTION_LABELS[r.action]||r.action)+'」的郵件複製到收件匣？\n\n寄件者：'+(r.sender||'（空）')+'\n收件者：'+(r.rcpt||'')+'\n主旨：'+(r.subject||'（無）')+(r.virus?'\n\n⚠ 這封曾命中病毒掃描。':'')+'\n\n原信已經在收件人的垃圾郵件匣，這個動作會再投遞一份乾淨的副本到收件匣，收件人會同時看到兩封。'))return;
    button.disabled=true;message('正在投遞副本…',false);
    SM.request('quarantine_copy',{id:r.id}).done(function(resp){
      message(resp.message||'已複製。',false);
    }).fail(failure).always(function(){button.disabled=false;});
  }
  // The black/white list dialog never sends an address: the server re-reads the
  // sender from the quarantine row by id, so the page can only list the sender of a
  // message that is actually held. Scope 'rcpt' writes a per-mailbox filterconf
  // entry, scope 'global' appends to the matching global rspamd map.
  var listModal=null, listCurrent=null;
  var LIST_MAP_LABELS={smtp:{wl:'SMTP 寄件人白名單',bl:'SMTP 寄件人黑名單'},mime:{wl:'From 寄件人白名單',bl:'From 寄件人黑名單'}};
  function listEscape(value){return value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/\//g,'\\/');}
  function listDomain(addr){var at=addr.lastIndexOf('@');return at<0?'':addr.slice(at+1).toLowerCase().replace(/\.$/,'');}
  function listEntry(){
    var r=listCurrent;if(!r)return null;
    var addr=String(r.sender||'').toLowerCase(),cond=el('sm-list-cond').value,scope=el('sm-list-scope').value;
    if(!addr||addr.indexOf('@')<0)return {error:'這封郵件的信封寄件者不是有效地址（'+(addr||'空寄件者')+'），無法自動建立條目。請改用「全域名單」分頁手動填寫。'};
    var d=listDomain(addr);
    if(cond!=='addr'&&!d)return {error:'無法從寄件者取出網域。'};
    if(scope==='rcpt'){
      if(cond==='subdomain')return {error:'個別信箱名單只支援「精確地址」與「整個網域」。要連子網域一起處理，請把範圍改成「全域」。'};
      return {value:cond==='addr'?addr:'*@'+d,target:r.rcpt+' 的'+(el('sm-list-kind').value==='wl'?'白':'黑')+'名單（filterconf）'};
    }
    var kind=el('sm-list-kind').value,match=el('sm-list-match').value;
    var rule=cond==='addr'?('/^'+listEscape(addr)+'$/i'):(cond==='subdomain'?('/@(?:[^@]+\\.)?'+listEscape(d)+'$/i'):('/@'+listEscape(d)+'$/i'));
    return {value:rule,target:'全域名單「'+LIST_MAP_LABELS[match][kind]+'」'};
  }
  function listRender(){
    var scope=el('sm-list-scope').value,kind=el('sm-list-kind').value;
    el('sm-list-match-wrap').hidden=(scope!=='global');
    var sub=el('sm-list-cond').querySelector('option[value=subdomain]');
    if(sub){sub.disabled=(scope==='rcpt');if(sub.disabled&&el('sm-list-cond').value==='subdomain')el('sm-list-cond').value='domain';}
    var e=listEntry(),box=el('sm-list-error');
    if(!e){el('sm-list-preview').textContent='';el('sm-list-target').textContent='';el('sm-list-effect').textContent='';return;}
    if(e.error){box.textContent=e.error;box.hidden=false;el('sm-list-preview').textContent='—';el('sm-list-target').textContent='';el('sm-list-effect').textContent='';el('sm-list-save').disabled=true;return;}
    box.hidden=true;el('sm-list-save').disabled=false;
    el('sm-list-target').textContent=e.target;
    el('sm-list-preview').textContent=e.value;
    el('sm-list-effect').textContent=scope==='global'
      ? (kind==='wl'?'命中時減 2050 分，等同強制放行，對全公司生效。':'命中時加 2050 分，等同強制拒收，對全公司生效。')
      : (kind==='wl'?'只對這個信箱放行該寄件者；同一寄件者寄給其他人不受影響。':'只對這個信箱拒收該寄件者；同一寄件者寄給其他人不受影響。');
  }
  function showList(r){
    if(!listModal)listModal=new bootstrap.Modal(el('sm-list-modal'));
    listCurrent=r;
    el('sm-list-sender').textContent=r.sender||'（空寄件者）';
    el('sm-list-rcpt').textContent=r.rcpt||'—';
    el('sm-list-subject').textContent=r.subject||'（無主旨）';
    el('sm-list-error').hidden=true;
    el('sm-list-kind').value='bl';el('sm-list-scope').value='global';el('sm-list-cond').value='addr';el('sm-list-match').value='smtp';
    listRender();
    listModal.show();
  }
  function listSave(button){
    var r=listCurrent,e=listEntry();if(!r||!e||e.error)return;
    var scope=el('sm-list-scope').value,kind=el('sm-list-kind').value;
    if(!window.confirm('確認加入'+e.target+'？\n\n條目：'+e.value+'\n\n'+el('sm-list-effect').textContent))return;
    button.disabled=true;
    var payload={id:r.id,kind:kind,cond:el('sm-list-cond').value,scope:scope};
    if(scope==='global')payload.match=el('sm-list-match').value;
    SM.request('quarantine_list',payload).done(function(resp){
      message(resp.message||'已加入名單。',false);
      if(listModal)listModal.hide();
      // Pull fresh maps/policies so the 全域名單 and 個別規則 tabs show the new entry.
      $.getJSON(api,{op:'state'}).done(function(d){
        if(!SM.state)return;
        SM.state.maps=d.data.maps;SM.state.policies=d.data.policies;SM.state.targets=d.data.targets;
        SM.state.scope_baselines=d.data.scope_baselines;SM.state.audit=d.data.audit;
        loadMapOptions();policies();summary();
      });
    }).fail(failure).always(function(){button.disabled=false;});
  }
  function releaseRejected(r,button){
    if(!window.confirm('確定放行這封被拒收的郵件？\n\n寄件者：'+(r.sender||'（空）')+'\n收件者：'+(r.rcpt||'')+'\n主旨：'+(r.subject||'（無）')+(r.virus?'\n\n⚠ 這封曾命中病毒掃描，放行將略過該攔截。':'')+'\n\n放行會把原信重新投遞到收件人信箱。'))return;
    button.disabled=true;message('正在放行郵件…',false);
    SM.request('release',{id:r.id}).done(function(resp){
      message(resp.message||'已放行。',false);
      rejectedRows=rejectedRows.filter(function(x){return x.id!==r.id;});renderRejected();rejectedStatus();
    }).fail(failure).always(function(){button.disabled=false;});
  }
  function loadRejected(){
    el('sm-rejected-status').textContent='正在讀取隔離區留存的郵件…';
    $.ajax({url:api,type:'GET',dataType:'json',timeout:20000,data:{op:'rejected'}}).done(function(r){rejectedLoaded=true;rejectedRows=r.data.rows||[];if(r.data.notify!==undefined)el('sm-rejected-notify').value=r.data.notify;rejectedStatus();renderRejected();}).fail(function(xhr,status){el('sm-rejected-status').textContent='清單讀取失敗，可按更新重試。';failure(xhr,status);});
  }
  var updatePolling=false;
  function setOverview(id,text,cls){var n=el(id);if(!n)return;n.textContent=text;n.className='small '+(cls||'text-muted');}
  var UPDATE_STEP_MARK={done:'✓',running:'●',warn:'!',pending:'○',skipped:'–'};
  var UPDATE_STEP_STATE={done:'完成',running:'進行中',warn:'有問題',pending:'尚未開始',skipped:'未執行'};
  var updateLogRaw='',updateStartedAt=null;
  function renderUpdateLog(){
    var pre=el('sm-update-log');if(!pre)return;
    var keyOnly=el('sm-update-key').checked,follow=el('sm-update-follow').checked;
    var atBottom=pre.scrollHeight-pre.scrollTop-pre.clientHeight<40;
    pre.replaceChildren();
    var lines=updateLogRaw?updateLogRaw.split('\n'):[],shown=0;
    lines.forEach(function(line){
      var cls='';
      if(/^==> /.test(line))cls='sm-l-step';
      else if(/^\s*!!|NEEDS-MANUAL|MISSING|FAIL|Fatal error|[Ee]rror:/.test(line))cls='sm-l-bad';
      else if(/（.*已摺疊）$/.test(line))cls='sm-l-fold';
      else if(/ PASS$|syntax OK|未發現問題|\bOK\b/.test(line))cls='sm-l-good';
      if(keyOnly&&cls!=='sm-l-step'&&cls!=='sm-l-bad')return;
      shown++;
      var span=node('span',line+'\n',cls||undefined);pre.appendChild(span);
    });
    if(!shown)pre.textContent=keyOnly?'（沒有步驟或問題行）':'（尚無紀錄）';
    if(follow&&(atBottom||keyOnly||!pre.dataset.seen))pre.scrollTop=pre.scrollHeight;
    pre.dataset.seen='1';
  }
  function renderUpdate(d){
    var host=el('sm-update-status'),states={idle:['尚未執行過更新','text-muted'],running:['更新進行中','text-warning'],done:['上次更新完成','text-success'],error:['上次更新有問題','text-danger'],rejected:['上次請求被拒絕','text-danger']};
    if(!d.available){host.textContent=d.message||'尚未啟用網頁更新。';host.className='small text-muted mb-2';el('sm-update-form').querySelector('button').disabled=true;el('sm-update-pass').disabled=true;setOverview('sm-ov-update',host.textContent);return;}
    var s=states[d.state]||states.idle,when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
    host.textContent=s[0]+when+(d.message?('：'+d.message):'');
    host.className='small mb-2 fw-semibold '+s[1];
    var busy=d.state==='running'||d.pending;
    el('sm-update-form').querySelector('button').disabled=busy;
    el('sm-update-pass').disabled=busy;
    var steps=d.steps||[],hasRun=!!(d.log||d.run_id);
    el('sm-update-progress').hidden=!hasRun;
    // steps
    var ol=el('sm-update-steps');ol.replaceChildren();
    steps.forEach(function(st){
      var li=node('li','',st.state);
      li.appendChild(node('span',UPDATE_STEP_MARK[st.state]||'○','sm-step-mark'));
      li.appendChild(document.createTextNode(st.n+'. '+st.title));
      li.appendChild(node('span',(UPDATE_STEP_STATE[st.state]||'')+(st.detail?'：'+st.detail:''),'sm-step-detail'));
      li.title=(UPDATE_STEP_STATE[st.state]||'')+(st.detail?'：'+st.detail:'');
      ol.appendChild(li);
    });
    // problems
    var pb=el('sm-update-problems');pb.replaceChildren();
    if((d.problems||[]).length){
      pb.appendChild(node('strong','這次更新發現 '+d.problems.length+' 項問題：'));
      var ul=node('ul','','mb-0 ps-3');d.problems.forEach(function(p){ul.appendChild(node('li',p));});pb.appendChild(ul);pb.hidden=false;
    }else pb.hidden=true;
    // version + elapsed
    var ver=el('sm-update-version');
    if(d.version_before&&d.version_after&&d.version_before!==d.version_after){ver.textContent='版本：'+d.version_before+' → '+d.version_after;ver.className='small text-success fw-semibold';}
    else if(d.version_before){ver.textContent='版本：'+(d.version_after||d.version_before)+(d.version_after?'（未變更）':'');ver.className='small text-muted';}
    else ver.textContent='';
    var m=/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/.exec(d.run_id||'');
    updateStartedAt=m?new Date(+m[1],+m[2]-1,+m[3],+m[4],+m[5],+m[6]):null;
    updateElapsed(busy,d.updated);
    // log
    updateLogRaw=d.log||'';
    el('sm-update-logmeta').textContent=updateLogRaw?('共 '+updateLogRaw.split('\n').length+' 行'+(d.log_truncated?('（較早的 '+d.log_truncated+' 行未顯示）'):'')+(busy?'，每 5 秒更新':'')):'';
    renderUpdateLog();
    // overview
    var ovText=s[0]+when+(d.version_after?('，版本 '+d.version_after):'')+((d.problems||[]).length?('，'+d.problems.length+' 項問題'):'');
    setOverview('sm-ov-update',ovText,busy?'text-warning':((d.problems||[]).length||d.state==='error'?'text-danger':'text-muted'));
    if(busy&&!updatePolling)pollUpdate();
  }
  function updateElapsed(busy,updated){
    var n=el('sm-update-elapsed');if(!n)return;
    if(!updateStartedAt){n.textContent='';return;}
    var end=busy?Date.now():(updated?updated*1000:Date.now()),sec=Math.max(0,Math.round((end-updateStartedAt.getTime())/1000));
    n.textContent=(busy?'已執行 ':'耗時 ')+Math.floor(sec/60)+' 分 '+(sec%60)+' 秒（開始於 '+updateStartedAt.toLocaleTimeString('zh-TW',{hour12:false})+'）';
  }
  function loadUpdate(){
    return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'update_status'}}).done(function(r){renderUpdate(r.data||{});});
  }
  function pollUpdate(){
    // The update recreates php-fpm, so requests will fail for a while; keep polling.
    updatePolling=true;
    var tries=0;
    (function tick(){
      tries++;
      $.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'update_status'}})
        .done(function(r){
          var d=r.data||{};renderUpdate(d);
          if(d.state==='running'||d.pending){setTimeout(tick,5000);}
          else{updatePolling=false;loadCustomizations();}
        })
        .fail(function(){
          el('sm-update-status').textContent='更新進行中，網頁服務重啟中…（已嘗試 '+tries+' 次重新連線）';
          el('sm-update-status').className='small text-warning mb-2';
          if(tries<240)setTimeout(tick,5000);else updatePolling=false;
        });
    })();
  }
  // ---- login-region allowlist ------------------------------------------------
  var geoState=null,geoDraft=null,geoDirty=false,geoPolling=false;
  var geoNames=null;try{geoNames=new Intl.DisplayNames(['zh-TW'],{type:'region'});}catch(e){}
  var GEO_SHORT={HK:'香港',MO:'澳門'};
  function ccName(cc){var n=GEO_SHORT[cc]||'';try{if(!n)n=geoNames?geoNames.of(cc):'';}catch(e){}return (n&&n!==cc)?(n+'（'+cc+'）'):cc;}
  function geoFmt(ts){return ts?new Date(ts*1000).toLocaleString('zh-TW',{hour12:false}):'—';}
  var GEO_QUICK=['JP','CN','HK','MO','US','KR','SG','VN','TH','MY','PH','ID','DE','GB'];
  // Everyday names people actually type that differ from the ICU zh-TW names.
  var GEO_ALIAS={'韓國':'KR','韩国':'KR','南韓':'KR','北韓':'KP','朝鮮':'KP','大陸':'CN','中國大陸':'CN','內地':'CN','台灣':'TW','臺灣':'TW','英國':'GB','美國':'US','日':'JP','港':'HK','澳':'MO','星':'SG','星加坡':'SG','星馬':'MY','大馬':'MY','荷蘭':'NL','紐西蘭':'NZ','杜拜':'AE','阿聯':'AE','usa':'US','uk':'GB','korea':'KR','south korea':'KR','hongkong':'HK','hong kong':'HK','macau':'MO','taiwan':'TW','vietnam':'VN','dubai':'AE','uae':'AE'};
  var geoNamesEn=null;try{geoNamesEn=new Intl.DisplayNames(['en'],{type:'region'});}catch(e){}
  function geoEn(cc){try{return geoNamesEn?(geoNamesEn.of(cc)||''):'';}catch(e){return '';}}
  function geoCountryList(){
    var list=(geoState&&geoState.available_countries)||[];
    return list.map(function(c){return {cc:c,name:ccName(c)};}).sort(function(a,b){
      var qa=GEO_QUICK.indexOf(a.cc),qb=GEO_QUICK.indexOf(b.cc);
      if(qa>=0||qb>=0)return (qa<0?99:qa)-(qb<0?99:qb);
      return a.name.localeCompare(b.name,'zh-Hant');});
  }
  function geoCountryOptions(){
    // A <datalist> behind a text input, not a <select>: typing 「日本」 or 「JP」 filters it,
    // and mailcow's bootstrap-select never touches it.
    var dl=el('sm-geo-cc-list');if(!dl)return;dl.replaceChildren();
    geoCountryList().forEach(function(x){var o=node('option');o.value=x.name;dl.appendChild(o);});
    var q=el('sm-geo-quick');if(q&&q.children.length<=1){GEO_QUICK.forEach(function(cc){if(((geoState&&geoState.available_countries)||[]).indexOf(cc)<0)return;
      var b=node('button',ccName(cc).replace(/（.*）$/,''),'btn btn-sm btn-outline-secondary py-0');b.type='button';b.title=ccName(cc);
      b.addEventListener('click',function(){el('sm-geo-temp-cc').value=ccName(cc);geoHint('sm-geo-temp-cc','sm-geo-temp-hint');});q.appendChild(b);});}
  }
  // Resolve what the admin typed: 「日本（JP）」 from the list, a bare code 「jp」, or a name
  // fragment 「日本」/「日」 as long as it matches exactly one country.
  function geoResolve(text){
    text=(text||'').trim();if(!text)return {err:'請輸入國家名稱或代碼'};
    var list=geoCountryList(),m=/（([A-Za-z]{2})）\s*$|\(([A-Za-z]{2})\)\s*$/.exec(text);
    var code=m?(m[1]||m[2]).toUpperCase():(/^[A-Za-z]{2}$/.test(text)?text.toUpperCase():'');
    if(code){var hit=list.filter(function(x){return x.cc===code;});return hit.length?{cc:code}:{err:'找不到代碼 '+code+' 的國家'};}
    var alias=GEO_ALIAS[text]||GEO_ALIAS[text.toLowerCase()];if(alias&&list.some(function(x){return x.cc===alias;}))return {cc:alias};
    var low=text.toLowerCase(),exact=list.filter(function(x){return x.name.replace(/（.*）$/,'').toLowerCase()===low||geoEn(x.cc).toLowerCase()===low;});
    if(exact.length===1)return {cc:exact[0].cc};
    var part=list.filter(function(x){return x.name.toLowerCase().indexOf(low)>=0;});
    if(part.length===1)return {cc:part[0].cc};
    if(!part.length)return {err:'找不到「'+text+'」，可改輸入兩碼代碼，例如 JP'};
    return {err:'符合「'+text+'」的有 '+part.length+' 個：'+part.slice(0,6).map(function(x){return x.name;}).join('、')+(part.length>6?'…':'')+'，請再打完整一點'};
  }
  function geoHint(inputId,hintId){
    var v=el(inputId).value,h=el(hintId);if(!h)return;
    if(!v.trim()){h.textContent='';h.className='small text-muted mb-1';return;}
    var r=geoResolve(v);h.textContent=r.cc?('→ '+ccName(r.cc)):r.err;h.className='small mb-1 '+(r.cc?'text-success':'text-danger');
  }
  function geoMarkDirty(){geoDirty=true;el('sm-geo-pending').hidden=false;renderGeoDraft();}
  function renderGeoDraft(){
    var d=geoDraft;if(!d)return;
    el('sm-geo-enabled').checked=!!d.enabled;
    var box=el('sm-geo-countries');box.replaceChildren();
    if(!d.countries.length)box.appendChild(node('span','（沒有常駐開放的國家）','small text-muted'));
    d.countries.forEach(function(cc){
      var b=node('span','','badge text-bg-success d-inline-flex align-items-center gap-1');b.appendChild(document.createTextNode(ccName(cc)));
      var x=node('button','×','btn btn-sm p-0 border-0 text-white lh-1');x.type='button';x.title='移除 '+ccName(cc);x.setAttribute('aria-label','移除 '+ccName(cc));
      x.addEventListener('click',function(){d.countries=d.countries.filter(function(c){return c!==cc;});geoMarkDirty();});
      b.appendChild(x);box.appendChild(b);
    });
    var tb=el('sm-geo-temp-rows');tb.replaceChildren();
    var nowS=Date.now()/1000;
    d.temporary=d.temporary.filter(function(e){return e.until>nowS;});
    if(!d.temporary.length){var tr=node('tr'),td=node('td','目前沒有臨時開放','small text-muted');td.colSpan=4;tr.appendChild(td);tb.appendChild(tr);}
    d.temporary.forEach(function(e,i){
      var tr=node('tr'),left=Math.ceil((e.until-nowS)/86400);
      tr.appendChild(node('td',ccName(e.cc),'small'));
      tr.appendChild(node('td',geoFmt(e.until)+'（剩 '+left+' 天）','small'));
      tr.appendChild(node('td',e.note||'','small text-muted'));
      var td=node('td','','sm-actions'),x=node('button','移除','btn btn-sm btn-outline-danger py-0');x.type='button';
      x.addEventListener('click',function(){d.temporary.splice(i,1);geoMarkDirty();});td.appendChild(x);tr.appendChild(td);tb.appendChild(tr);
    });
    geoCountryOptions();
  }
  function renderGeo(d){
    geoState=d;var st=el('sm-geo-status');
    var form=el('sm-geo-form'),btn=form.querySelector('button');
    if(!d.configured){st.textContent=d.message||'尚未安裝登入地區限制。';st.className='small fw-semibold mb-2 text-warning';btn.disabled=true;setOverview('sm-ov-geo',st.textContent,'text-warning');return;}
    var cls={enforcing:'text-success',disabled:'text-muted',error:'text-danger',rejected:'text-danger'}[d.state]||'text-muted';
    st.textContent=(d.pending?'變更處理中… ':'')+(d.message||'')+(d.state==='rejected'?'（上次的變更未套用）':'');st.className='small fw-semibold mb-2 '+cls;
    btn.disabled=!!d.pending;
    if(!geoDirty||!geoDraft){var p=d.policy||{};geoDraft={enabled:!!p.enabled,countries:(p.countries||[]).slice(),temporary:(p.temporary||[]).map(function(e){return {cc:e.cc,until:e.until,note:e.note||''};})};el('sm-geo-pending').hidden=true;}
    renderGeoDraft();
    el('sm-geo-ports').replaceChildren();(d.ports||[]).forEach(function(x){el('sm-geo-ports').appendChild(node('span',x.port+' '+x.name,'badge text-bg-secondary me-1 mb-1'));});
    el('sm-geo-open').replaceChildren();(d.open_ports||[]).forEach(function(x){el('sm-geo-open').appendChild(node('span',x.port+' '+x.name,'badge text-bg-light border me-1 mb-1'));});
    var c=d.counters||{};el('sm-geo-counts').textContent=d.active?('（自上次套用：擋下 '+(c.dropped||0)+'、放行 '+(c.passed||0)+' 個連線）'):'';
    var by=el('sm-geo-bycc');by.replaceChildren();Object.keys(d.blocked_by_country||{}).forEach(function(cc){by.appendChild(node('span',ccName(cc)+' '+d.blocked_by_country[cc],'badge text-bg-danger'));});
    var tb=el('sm-geo-blocked');tb.replaceChildren();
    var rows=d.blocked_recent||[];
    if(!rows.length){var tr=node('tr'),td=node('td',d.active?'過去 24 小時沒有被擋的連線':'未啟用','small text-muted');td.colSpan=5;tr.appendChild(td);tb.appendChild(tr);}
    rows.forEach(function(r){var tr=node('tr');tr.appendChild(node('td',r.ip,'small font-monospace'));tr.appendChild(node('td',ccName(r.cc||'??'),'small'));tr.appendChild(node('td',String(r.count),'small'));
      tr.appendChild(node('td',(r.ports||[]).map(function(p){var f=(d.ports||[]).find(function(x){return x.port===p;});return f?f.name:String(p);}).join('、'),'small'));tr.appendChild(node('td',geoFmt(r.last),'small'));tb.appendChild(tr);});
    el('sm-geo-meta').textContent='國家 IP 資料更新於 '+geoFmt(d.data_fetched)+'；規則套用於 '+geoFmt(d.applied)+(d.set_v4?('，IPv4 範圍 '+d.set_v4+' 筆'):'')+'。每 10 分鐘自動檢查一次，臨時開放到期會自動關閉。';
    var ov=d.state==='enforcing'?('啟用中：只開放 '+(d.effective||[]).map(ccName).join('、')+((rows.length)?('；24 小時擋下 '+rows.length+' 個來源'):'')):(d.message||'');
    setOverview('sm-ov-geo',ov,cls);
    if(d.pending&&!geoPolling)pollGeo();
  }
  function loadGeo(){return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'geo'}}).done(function(r){renderGeo(r.data||{});}).fail(function(xhr,status){cardFail('sm-geo-status',xhr,status);});}
  function pollGeo(){geoPolling=true;var tries=0;(function tick(){tries++;$.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'geo'}}).done(function(r){var d=r.data||{};if(d.pending&&tries<60){setTimeout(tick,2000);return;}geoPolling=false;geoDirty=false;renderGeo(d);}).fail(function(){if(tries<60)setTimeout(tick,3000);else geoPolling=false;});})();}
  function submitGeo(){
    var d=geoDraft;if(!d)return;
    var pass=el('sm-geo-pass').value;if(!pass){message('請輸入更新密碼。',true);el('sm-geo-pass').focus();return;}
    var all=d.countries.concat(d.temporary.map(function(e){return e.cc;}));
    if(d.enabled&&!all.length){message('啟用時至少要開放一個國家，否則所有外部登入都會被擋。',true);return;}
    var lines=d.enabled?('啟用後，只有下列國家可以登入：\n  '+(d.countries.map(ccName).join('、')||'（無）')+(d.temporary.length?('\n臨時開放：\n  '+d.temporary.map(function(e){return ccName(e.cc)+' 到 '+geoFmt(e.until);}).join('\n  ')):'')):'停用後，所有國家都可以連線登入。';
    if(!window.confirm('確定套用登入地區設定？\n\n'+lines+'\n\n廠商寄信（25 埠）與公司內網不受影響。'))return;
    var btn=el('sm-geo-form').querySelector('button');
    save('geo_request',{enabled:d.enabled,countries:d.countries,temporary:d.temporary,passphrase:pass},btn,function(){el('sm-geo-pass').value='';geoDirty=false;pollGeo();});
  }
  var nasPolling=false;
  function renderNas(d){
    var host=el('sm-nas-status');
    var states={idle:['尚未備份過','text-muted'],running:['備份進行中…','text-warning'],done:['上次備份完成','text-success'],error:['上次備份失敗','text-danger'],rejected:['上次請求被拒絕','text-danger']};
    var form=el('sm-nas-form'),btn=form.querySelector('button');
    if(!d.available||!d.configured){
      host.textContent=d.message||'尚未啟用網頁備份。';
      setOverview('sm-ov-backup',host.textContent,'text-warning');
      host.className='small text-warning mb-2';
      el('sm-nas-meta').hidden=true;
      btn.disabled=true;
      return;
    }
    var s=states[d.state]||states.idle;
    var when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
    host.textContent=s[0]+when+(d.message?('：'+d.message):'');
    host.className='small mb-2 '+s[1];
    el('sm-nas-meta').hidden=false;
    setOverview('sm-ov-backup',host.textContent,s[1]);
    el('sm-nas-target').textContent=d.target||'—';
    el('sm-nas-retention').textContent=(d.retention!==null&&d.retention!==undefined)?(d.retention+' 份'):'—';
    el('sm-nas-schedule').textContent=d.schedule||'—';
    var encEl=el('sm-nas-encrypted');
    if(d.encrypted===true){encEl.textContent='AES256（金鑰只在主機，不在 NAS 上）';encEl.className='col-sm-9 mb-0 text-success';}
    else if(d.encrypted===false){encEl.textContent='未加密';encEl.className='col-sm-9 mb-0 text-danger';}
    else{encEl.textContent='—';encEl.className='col-sm-9 mb-0';}
    var busy=d.state==='running'||d.pending;
    btn.disabled=busy;
    var tbody=el('sm-nas-rows');tbody.replaceChildren();
    if(!d.backups||!d.backups.length){
      var tr=document.createElement('tr'),td=document.createElement('td');
      td.colSpan=2;td.className='text-muted small';
      td.textContent=(d.state==='idle')?'尚未備份過，按「立即備份」或等排程執行。':'尚無備份清單（上次備份可能未完成）。';
      tr.appendChild(td);tbody.appendChild(tr);
    }else{
      d.backups.forEach(function(b,i){
        var tr=document.createElement('tr');
        var td1=document.createElement('td');
        td1.textContent=b.name||'';
        if(i===0){var tag=document.createElement('span');tag.className='badge bg-success ms-2';tag.textContent='最新';td1.appendChild(tag);}
        var td2=document.createElement('td');td2.className='text-end';td2.textContent=b.size||'';
        tr.appendChild(td1);tr.appendChild(td2);tbody.appendChild(tr);
      });
    }
    if(d.notify!==undefined&&document.activeElement!==el('sm-nas-notify'))el('sm-nas-notify').value=d.notify||'';
    fillRestoreBackups(d.backups);
    var lg=el('sm-nas-log');
    if(d.log){lg.hidden=false;lg.textContent=d.log;lg.scrollTop=lg.scrollHeight;}else{lg.hidden=true;}
    if(busy&&!nasPolling)pollNas();
  }
  function loadNas(){
    return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'nas_backup'}}).done(function(r){renderNas(r.data||{});});
  }
  function pollNas(){
    // A backup stops dovecot/postfix/redis/rspamd for a while, so requests may fail.
    nasPolling=true;
    var tries=0;
    (function tick(){
      tries++;
      $.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'nas_backup'}})
        .done(function(r){
          var d=r.data||{};renderNas(d);
          if(d.state==='running'||d.pending){setTimeout(tick,5000);}else{nasPolling=false;}
        })
        .fail(function(){
          el('sm-nas-status').textContent='備份進行中，服務重啟中…（已嘗試 '+tries+' 次重新連線）';
          el('sm-nas-status').className='small text-warning mb-2';
          if(tries<360)setTimeout(tick,5000);else nasPolling=false;
        });
    })();
  }
  var restorePolling=false, restoreBackups=[];
  var COMPONENT_LABELS={mysql:'資料庫（帳號、網域、設定）',redis:'Redis（執行期設定）',rspamd:'Rspamd（規則與統計）',postfix:'Postfix（佇列與對應表）'};
  function renderRestore(d){
    var host=el('sm-restore-status');
    var states={idle:['尚未還原過','text-muted'],running:['還原進行中…','text-warning'],done:['上次還原完成','text-success'],error:['上次還原失敗','text-danger'],rejected:['上次請求被拒絕','text-danger']};
    var form=el('sm-restore-form'),btn=form.querySelector('button');
    if(!d.available){host.textContent=d.message||'尚未啟用網頁還原。';host.className='small text-warning mb-2';btn.disabled=true;return;}
    var s=states[d.state]||states.idle;
    var when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
    host.textContent=s[0]+when+(d.message?('：'+d.message):'')+(d.snapshot?('　還原前快照：'+d.snapshot):'');
    host.className='small mb-2 '+s[1];
    var busy=d.state==='running'||d.pending;
    btn.disabled=busy;
    ['sm-restore-backup','sm-restore-confirm','sm-restore-pass'].forEach(function(id){el(id).disabled=busy;});
    var box=el('sm-restore-components');
    if(!box.dataset.built){
      (d.allowed||[]).forEach(function(c){
        var lab=document.createElement('label');lab.className='form-check d-flex align-items-center gap-1 mb-0';
        var cb=document.createElement('input');cb.type='checkbox';cb.className='form-check-input mt-0';cb.value=c;cb.checked=(c==='mysql');
        var sp=document.createElement('span');sp.className='form-check-label';sp.textContent=COMPONENT_LABELS[c]||c;
        lab.appendChild(cb);lab.appendChild(sp);box.appendChild(lab);
      });
      box.dataset.built='1';
    }
    box.querySelectorAll('input').forEach(function(i){i.disabled=busy;});
    var lg=el('sm-restore-log');
    if(d.log){lg.hidden=false;lg.textContent=d.log;lg.scrollTop=lg.scrollHeight;}else{lg.hidden=true;}
    if(busy&&!restorePolling)pollRestore();
  }
  function fillRestoreBackups(list){
    restoreBackups=list||[];
    var sel=el('sm-restore-backup'),cur=sel.value;
    var rbtn=el('sm-restore-form').querySelector('button[type="submit"]');
    if(rbtn)rbtn.disabled=!restoreBackups.length;
    sel.replaceChildren();
    if(!restoreBackups.length){
      var o=document.createElement('option');o.value='';o.textContent='（NAS 上尚無備份）';sel.appendChild(o);return;
    }
    restoreBackups.forEach(function(b,i){
      var o=document.createElement('option');o.value=b.name;
      o.textContent=b.name+(b.size?('  ('+b.size+')'):'')+(i===0?'  ← 最新':'');
      sel.appendChild(o);
    });
    if(cur&&restoreBackups.some(function(b){return b.name===cur;}))sel.value=cur;
  }
  function loadRestore(){
    return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'nas_restore'}}).done(function(r){renderRestore(r.data||{});});
  }
  function pollRestore(){
    restorePolling=true;
    var tries=0;
    (function tick(){
      tries++;
      $.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'nas_restore'}})
        .done(function(r){
          var d=r.data||{};renderRestore(d);
          if(d.state==='running'||d.pending){setTimeout(tick,5000);}
          else{restorePolling=false;loadState();loadCustomizations();}
        })
        .fail(function(){
          el('sm-restore-status').textContent='還原進行中，服務重啟中…（已嘗試 '+tries+' 次重新連線）';
          el('sm-restore-status').className='small text-warning mb-2';
          if(tries<360)setTimeout(tick,5000);else restorePolling=false;
        });
    })();
  }
  var hostPolling=false;
  function renderHost(d){
    var host=el('sm-host-status');
    var states={idle:['主機更新狀態','text-muted'],checking:['正在檢查…','text-warning'],
                applying:['正在套用主機更新…','text-warning'],rebooting:['主機即將重開機…','text-danger'],
                done:['上次主機更新完成','text-success'],error:['上次主機更新有問題','text-danger'],
                rejected:['上次請求被拒絕','text-danger']};
    var form=el('sm-host-form'),applyBtn=form.querySelector('button[type="submit"]'),
        rebootBtn=el('sm-host-reboot-btn'),pass=el('sm-host-pass');
    if(!d.available||!d.configured){
      host.textContent=d.message||'尚未啟用網頁主機更新。';
      host.className='small text-muted mb-2';
      el('sm-host-counts').hidden=true;el('sm-host-deferred').hidden=true;el('sm-host-reboot').hidden=true;
      applyBtn.disabled=true;rebootBtn.disabled=true;
      return;
    }
    var s=states[d.state]||states.idle;
    var when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
    host.textContent=s[0]+when+(d.message?('：'+d.message):'');
    host.className='small mb-2 '+s[1];
    el('sm-host-counts').hidden=false;
    el('sm-host-count').textContent=(d.count===null||d.count===undefined)?'—':(d.count+' 個');
    el('sm-host-security').textContent=(d.security===null||d.security===undefined)?'—':(d.security+' 個');
    el('sm-host-kernel').textContent=d.kernel_running||'—';
    var def=el('sm-host-deferred');
    if(d.deferred&&d.deferred.length){
      def.hidden=false;def.className='small mb-2 text-warning';
      def.textContent='延後中（需按「套用主機更新」才會升級，因為會重啟容器）：'+d.deferred.join('、');
    }else{def.hidden=true;}
    var rb=el('sm-host-reboot');
    if(d.reboot_required){
      rb.hidden=false;rb.className='small mb-2 text-danger';
      rb.textContent='有更新需重開機才生效'+(d.reboot_pkgs?('：'+d.reboot_pkgs):'')
        +(d.kernel_installed&&d.kernel_installed!==d.kernel_running?('　已安裝核心 '+d.kernel_installed):'');
    }else{rb.hidden=true;}
    var busy=d.state==='applying'||d.state==='rebooting'||d.pending;
    applyBtn.disabled=busy;pass.disabled=busy;
    rebootBtn.disabled=busy||!d.reboot_required;
    var lg=el('sm-host-log');
    if(d.log){lg.hidden=false;lg.textContent=d.log;lg.scrollTop=lg.scrollHeight;}else{lg.hidden=true;}
    if(busy&&!hostPolling)pollHost();
  }
  function loadHost(){
    return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'host_update'}}).done(function(r){renderHost(r.data||{});});
  }
  function pollHost(){
    // Applying restarts the container runtime and a reboot takes the box down, so
    // requests will fail for a while. Keep retrying rather than declaring failure.
    hostPolling=true;
    var tries=0;
    (function tick(){
      tries++;
      $.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'host_update'}})
        .done(function(r){
          var d=r.data||{};renderHost(d);
          if(d.state==='applying'||d.state==='rebooting'||d.pending){setTimeout(tick,5000);}
          else{hostPolling=false;}
        })
        .fail(function(){
          el('sm-host-status').textContent='主機維護進行中，服務重啟中…（已嘗試 '+tries+' 次重新連線）';
          el('sm-host-status').className='small text-warning mb-2';
          if(tries<360)setTimeout(tick,5000);else hostPolling=false;
        });
    })();
  }
  function submitHost(action,confirmText){
    var pass=el('sm-host-pass').value;
    if(!pass){message('請輸入更新密碼。',true);return;}
    if(!window.confirm(confirmText))return;
    var applyBtn=el('sm-host-form').querySelector('button[type="submit"]');
    var rebootBtn=el('sm-host-reboot-btn');
    applyBtn.disabled=true;rebootBtn.disabled=true;
    SM.request('host_update_request',{action:action,passphrase:pass}).done(function(r){
      el('sm-host-pass').value='';
      message(r.message||'已送出請求。',false);
      pollHost();
    }).fail(function(xhr,status){cardFail('sm-host-status',xhr,status);applyBtn.disabled=false;rebootBtn.disabled=false;});
  }
  function cardFail(statusId, xhr, status) {
    failure(xhr, status);
    var n = el(statusId);
    if (!n) return;
    var msg = (status === 'timeout')
      ? '等待伺服器回應逾時，請重新讀取確認結果。'
      : (((xhr || {}).responseJSON || {}).message || '操作失敗，請確認登入狀態。');
    n.textContent = msg;
    n.className = 'small mb-2 text-danger';
  }
  function refreshAll(){
    loadState();loadCustomizations();loadUpdate();loadHost();loadGeo();
    loadNasSetup();loadNas();loadRestore();
  }
  var nasSetupPolling=false;
  function renderNasSetup(d){
    var host=el('sm-nassetup-status');
    var states={idle:['尚未透過網頁設定過','text-muted'],running:['正在套用並測試連線…','text-warning'],
                done:['設定完成','text-success'],error:['設定失敗','text-danger'],
                rejected:['請求被拒絕','text-danger']};
    var form=el('sm-nassetup-form'),btn=form.querySelector('button[type="submit"]');
    var fields=['sm-nassetup-host','sm-nassetup-share','sm-nassetup-path','sm-nassetup-user',
                'sm-nassetup-pass','sm-nassetup-domain','sm-nassetup-vers','sm-nassetup-keep',
                'sm-nassetup-passphrase'];
    var sel=el('sm-nassetup-vers');
    if(!sel.dataset.built&&d.versions&&d.versions.length){
      d.versions.forEach(function(v){
        var o=document.createElement('option');o.value=v;o.textContent=v;
        if(v==='3.0')o.selected=true;
        sel.appendChild(o);
      });
      sel.dataset.built='1';
    }
    el('sm-nassetup-hint').hidden=!!d.available;
    if(!d.available){
      host.textContent=d.message||'尚未啟用網頁設定 NAS。';
      host.className='small text-warning mb-2';
    }else{
      var s=states[d.state]||states.idle;
      var when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
      host.textContent=s[0]+when+(d.message?('：'+d.message):'');
      host.className='small mb-2 '+s[1];
    }
    var busy=d.state==='running'||d.pending;
    // Only submission is gated; the inputs remain usable so values can be prepared.
    btn.disabled=busy||!d.available;
    fields.forEach(function(i){el(i).disabled=busy;});
    var lg=el('sm-nassetup-log');
    if(d.log){lg.hidden=false;lg.textContent=d.log;lg.scrollTop=lg.scrollHeight;}else{lg.hidden=true;}
    if(busy&&!nasSetupPolling)pollNasSetup();
  }
  function loadNasSetup(){
    return $.ajax({url:api,type:'GET',dataType:'json',timeout:15000,data:{op:'nas_setup'}}).done(function(r){renderNasSetup(r.data||{});});
  }
  function pollNasSetup(){
    nasSetupPolling=true;
    var tries=0;
    (function tick(){
      tries++;
      $.ajax({url:api,type:'GET',dataType:'json',timeout:10000,data:{op:'nas_setup'}})
        .done(function(r){
          var d=r.data||{};renderNasSetup(d);
          if(d.state==='running'||d.pending){setTimeout(tick,3000);}
          else{nasSetupPolling=false;loadNas();loadRestore();}
        })
        .fail(function(){ if(tries<60)setTimeout(tick,3000); else nasSetupPolling=false; });
    })();
  }
  function renderCustomizations(items){
    var tbody=el('sm-custom-rows');tbody.replaceChildren();
    var bad=items.filter(function(i){return i.status!=='ok';}).length;
    var labels={ok:['正常','bg-success'],missing:['已遺失','bg-danger'],unknown:['無法檢查','bg-secondary']};
    items.forEach(function(i){
      var tr=node('tr'),td=node('td');
      td.appendChild(node('div',i.name,'small'));
      if(i.detail)td.appendChild(node('div',i.detail,'small text-muted'));
      tr.appendChild(td);
      var st=node('td','',' sm-actions'),lab=labels[i.status]||labels.unknown;
      st.appendChild(node('span',lab[0],'badge '+lab[1]));tr.appendChild(st);
      tbody.appendChild(tr);
    });
    el('sm-custom-status').textContent=bad?('有 '+bad+' 項自訂設定不在預期狀態，可能被更新覆蓋。'):'全部 '+items.length+' 項自訂設定都在。';
    el('sm-custom-status').className='small mb-2 '+(bad?'text-danger':'text-muted');
    setOverview('sm-ov-verify',el('sm-custom-status').textContent,bad?'text-danger':'text-muted');
  }
  function loadCustomizations(){
    el('sm-custom-status').textContent='正在檢查本機自訂設定…';el('sm-custom-status').className='small text-muted mb-2';
    $.ajax({url:api,type:'GET',dataType:'json',timeout:20000,data:{op:'customizations'}}).done(function(r){renderCustomizations(r.data.items||[]);}).fail(function(xhr,status){el('sm-custom-status').textContent='自訂設定檢查失敗，可按重新檢查重試。';el('sm-custom-status').className='small text-danger mb-2';failure(xhr,status);});
  }
  function outboundStatus(){
    el('sm-outbound-status').textContent='共 '+outboundRows.length+' 封往外寄被攔截的郵件（保留 30 天）。放行會寄給外部收件人並略過當初攔截；SMTP 連線階段拒收不會出現在此。';
  }
  function renderOutbound(){
    var term=el('sm-outbound-search').value.toLowerCase(),tbody=el('sm-outbound-rows');tbody.replaceChildren();
    var rows=outboundRows.filter(function(r){return [r.sender,r.rcpt,r.subject,r.user].join(' ').toLowerCase().indexOf(term)>=0;});
    if(!rows.length){var tr=node('tr'),td=node('td',outboundRows.length?'沒有符合搜尋的郵件。':'目前沒有被攔截的外寄郵件。');td.colSpan=4;td.className='small text-muted';tr.appendChild(td);tbody.appendChild(tr);return;}
    rows.forEach(function(r){
      var tr=node('tr');
      tr.appendChild(node('td',r.created?new Date(r.created*1000).toLocaleString('zh-TW',{hour12:false}):'—','small'));
      var td=node('td');td.appendChild(node('div',(r.sender||'（空寄件者）')+' → '+(r.rcpt||''),'small'));
      var subject=node('div',r.subject||'（無主旨）','small text-muted sm-subject');subject.title=r.subject||'';td.appendChild(subject);
      if(r.virus){td.appendChild(node('span','病毒命中','badge bg-danger'));}
      tr.appendChild(td);
      tr.appendChild(node('td',Number(r.score).toFixed(2)));
      td=node('td','',' sm-actions');
      var view=node('a','檢視','btn btn-sm btn-outline-secondary me-1');view.href='/qpreview.php?outbound_id='+encodeURIComponent(r.id);view.target='_blank';view.rel='noopener noreferrer';td.appendChild(view);
      var rel=node('button','放行','btn btn-sm btn-outline-primary me-1');rel.type='button';rel.addEventListener('click',function(){releaseOutbound(r,rel);});td.appendChild(rel);
      var del=node('button','刪除','btn btn-sm btn-outline-danger');del.type='button';del.addEventListener('click',function(){deleteOutbound(r,del);});td.appendChild(del);
      tr.appendChild(td);tbody.appendChild(tr);
    });
  }
  function releaseOutbound(r,button){
    var warn='確定放行這封往外寄的郵件，寄給外部收件人？\n\n寄件者：'+(r.sender||'（空）')+'\n外部收件者：'+(r.rcpt||'')+'\n主旨：'+(r.subject||'（無）')+'\n\n放行會把原信寄出，略過當初的攔截。';
    if(!window.confirm(warn))return;
    var payload={id:r.id};
    if(r.virus){ if(!window.confirm('⚠ 這封外寄信命中病毒掃描。\n\n放行會把可能含惡意內容的郵件寄給外部收件人 '+(r.rcpt||'')+'。\n\n你確定仍要放行嗎？'))return; payload.confirm_virus=true; }
    button.disabled=true;message('正在放行並寄出…',false);
    SM.request('outbound_release',payload).done(function(resp){
      message(resp.message||'已放行。',false);
      outboundRows=outboundRows.filter(function(x){return x.id!==r.id;});renderOutbound();outboundStatus();
    }).fail(failure).always(function(){button.disabled=false;});
  }
  function deleteOutbound(r,button){
    if(!window.confirm('確定刪除這封被攔截的外寄郵件？刪除後不會寄出，也無法復原。\n\n收件者：'+(r.rcpt||'')+'\n主旨：'+(r.subject||'（無）')))return;
    button.disabled=true;message('正在刪除…',false);
    SM.request('outbound_delete',{id:r.id}).done(function(resp){
      message(resp.message||'已刪除。',false);
      outboundRows=outboundRows.filter(function(x){return x.id!==r.id;});renderOutbound();outboundStatus();
    }).fail(failure).always(function(){button.disabled=false;});
  }
  function loadOutbound(){
    el('sm-outbound-status').textContent='正在讀取外寄攔截清單…';
    $.ajax({url:api,type:'GET',dataType:'json',timeout:20000,data:{op:'outbound'}}).done(function(r){outboundLoaded=true;outboundRows=r.data.rows||[];if(r.data.notify!==undefined)el('sm-outbound-notify').value=r.data.notify;outboundStatus();renderOutbound();}).fail(function(xhr,status){el('sm-outbound-status').textContent='清單讀取失敗，可按更新重試。';failure(xhr,status);});
  }
  function loadState() {
    el('sm-refresh').disabled=true;
    $.ajax({url:api,type:'GET',dataType:'json',timeout:45000,data:{op:'state'}}).done(function(r){SM.state=r.data;drafts={};actions();symbols();loadMapOptions();policies();summary();message(r.data.errors.length?r.data.errors.join('；'):'已讀取目前生效設定。調整只在按下各區儲存後寫入。',!!r.data.errors.length);}).fail(failure).always(function(){el('sm-refresh').disabled=false;});
  }
  $(function(){
    if(!el('spam-manager'))return;
    $('#spam-manager form').off('submit');
    $('#spam-manager select').each(function(){if($(this).data('selectpicker'))$(this).selectpicker('destroy');});
    document.querySelectorAll('[data-sm-panel],[data-sm-go]').forEach(function(b){b.addEventListener('click',function(){openPanel(b.getAttribute('data-sm-panel')||b.getAttribute('data-sm-go'));});});
    el('sm-refresh').addEventListener('click',function(){if(Object.keys(drafts).length || (mapFile && SM.state && el('sm-map-content').value!==SM.state.maps[mapFile].content)){if(!window.confirm('重新讀取會捨棄尚未儲存的權重與名單內容，是否繼續？'))return;}refreshAll();});
    el('sm-actions-form').addEventListener('submit',function(e){e.preventDefault();if(!SM.state || !SM.state.actions)return;save('save_actions',{values:{greylist:el('sm-grey').value,'add header':el('sm-tag').value,reject:el('sm-reject').value},baseline:SM.state.actions},this.querySelector('button'),function(d){SM.state.actions=d.actions;actions();summary();});});
    ['sm-grey','sm-tag','sm-reject'].forEach(function(id){el(id).addEventListener('input',simulate);});
    el('sm-symbol-search').addEventListener('input',function(){page=0;symbols();});el('sm-symbol-prev').addEventListener('click',function(){page--;symbols();});el('sm-symbol-next').addEventListener('click',function(){page++;symbols();});
    el('sm-sim-clear').addEventListener('click',function(){selected={};symbols();simulate();});
    el('sm-save-symbols').addEventListener('click',function(){var originals={};SM.state.symbols.forEach(function(s){originals[s.name]=s.weight;});var changes=Object.keys(drafts).map(function(k){return {name:k,value:drafts[k],baseline:originals[k]};});save('save_symbols',{changes:changes},this,function(){changes.forEach(function(c){SM.state.symbols.find(function(s){return s.name===c.name;}).weight=Number(c.value);});drafts={};symbols();simulate();});});
    el('sm-map-select').addEventListener('change',function(){if(mapFile && el('sm-map-content').value!==SM.state.maps[mapFile].content && !window.confirm('切換名單會捨棄未儲存內容，是否繼續？')){this.value=mapFile;return;}showMap();});
    el('sm-map-content').addEventListener('input',mapCount);
    // The helper escapes the input and emits the entry the selected map expects, so
    // admins never have to hand-write a regex. The backend re-validates every line.
    function mapEscape(value){return value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/\//g,'\\/');}
    function mapRule(family,kind,raw){
      if(family==='address'){
        if(kind==='addr'){
          if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw))throw '請輸入完整郵件地址，例如 sender@example.com。';
          return '/^'+mapEscape(raw)+'$/i';
        }
        if(kind==='local'){
          if(!/^[^\s@]+$/.test(raw))throw '請只輸入 @ 之前的帳號部分，例如 newsletter。';
          return '/^'+mapEscape(raw)+'@/i';
        }
        var d=mapDomain(raw);
        return kind==='subdomain'?'/@(?:[^@]+\\.)?'+mapEscape(d)+'$/i':'/@'+mapEscape(d)+'$/i';
      }
      if(family==='host'){
        var h=mapDomain(raw);
        return kind==='hostsuffix'?'/(?:^|\\.)'+mapEscape(h)+'$/i':'/^'+mapEscape(h)+'$/i';
      }
      if(family==='ip'){
        if(kind==='cidr'){
          if(!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(raw))throw '請輸入網段，例如 203.0.113.0/24。';
        }else if(!/^[0-9a-fA-F:.]+$/.test(raw)||raw.indexOf('/')>=0){throw '請輸入單一 IP 位址，例如 203.0.113.7。';}
        return raw;
      }
      var parts=raw.replace(/^AS/i,'').split(/\s+/).filter(Boolean);
      if(kind==='asnscore'){
        if(parts.length!==2||!/^\d+$/.test(parts[0])||!/^-?\d+(\.\d+)?$/.test(parts[1]))throw '請輸入「ASN 倍數」，例如 12874 2。';
        return parts[0]+' '+parts[1];
      }
      if(parts.length!==1||!/^\d+$/.test(parts[0]))throw '請只輸入 ASN 數字，例如 12874。';
      return parts[0];
    }
    function mapDomain(raw){
      var d=raw.replace(/^@/,'').replace(/\.$/,'');
      if(!/^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(d))throw '請輸入有效的網域或主機名，例如 example.com。';
      return d;
    }
    el('sm-map-kind').addEventListener('change',function(){
      var m=SM.state&&SM.state.maps[mapFile];if(!m)return;
      var c=MAP_CONDITIONS[mapFamily(m)].find(function(x){return x.v===this.value;},this);
      if(c)el('sm-map-address').placeholder=c.p;
    });
    el('sm-map-insert').addEventListener('click',function(){
      var m=SM.state&&SM.state.maps[mapFile];if(!m)return;
      var rule;
      try{rule=mapRule(mapFamily(m),el('sm-map-kind').value,el('sm-map-address').value.trim());}
      catch(err){message(err,true);return;}
      var area=el('sm-map-content');
      if(area.value.split(/\r?\n/).some(function(line){return line.trim()===rule;})){message('這條規則已在名單中：'+rule,true);return;}
      area.value=area.value.replace(/\s*$/,'')+'\n'+rule+'\n';mapCount();
      el('sm-map-address').value='';
      message('已加入 '+rule+'，請按「驗證並儲存名單」實際寫入。',false);
    });
    el('sm-map-form').addEventListener('submit',function(e){e.preventDefault();if(!SM.state || !SM.state.maps[mapFile])return;var file=mapFile;save('save_map',{file:file,content:el('sm-map-content').value,baseline:SM.state.maps[file].hash},this.querySelector('button[type=submit]'),function(d){SM.state.maps[file]=d.map;loadMapOptions();summary();});});
    el('sm-scope').addEventListener('change',scope);
    el('sm-policy-form').addEventListener('submit',function(e){e.preventDefault();save('policy_add',{object:el('sm-scope').value.trim(),kind:el('sm-policy-kind').value,value:el('sm-policy-value').value},this.querySelector('button'),refreshPolicies);});
    function saveScope(reset,button){var target=el('sm-scope').value.trim();save('scope_score',{object:target,tag:el('sm-scope-tag').value,reject:el('sm-scope-reject').value,reset:reset,baseline:(SM.state.scope_baselines||{})[target]},button,refreshPolicies);}
    el('sm-scope-form').addEventListener('submit',function(e){e.preventDefault();saveScope(false,this.querySelector('button'));});el('sm-scope-reset').addEventListener('click',function(){saveScope(true,this);});
    el('sm-history-search').addEventListener('input',renderHistory);el('sm-history-refresh').addEventListener('click',loadHistory);
    el('sm-rejected-search').addEventListener('input',renderRejected);el('sm-rejected-refresh').addEventListener('click',loadRejected);
    el('sm-rejected-action').value='all'; // browsers restore the last-chosen option on reload; always start from 全部
    el('sm-rejected-action').addEventListener('change',function(){rejectedStatus();renderRejected();});
    el('sm-msg-release').addEventListener('click',function(){
      if(!msgCurrent||msgCurrent.action!=='reject')return;
      var r=msgCurrent;
      releaseRejected(r,this);
      if(msgModal)msgModal.hide();
    });
    el('sm-msg-copy').addEventListener('click',function(){
      if(!msgCurrent||msgCurrent.action==='reject')return;
      var r=msgCurrent;
      copyToInbox(r,this);
      if(msgModal)msgModal.hide();
    });
    // Reading the message and listing its sender are separate steps on purpose: the
    // content modal closes first so the decision is made against the list dialog's
    // own preview of the entry that will be written.
    el('sm-msg-list').addEventListener('click',function(){
      if(!msgCurrent)return;
      var r=msgCurrent;
      if(!msgModal){showList(r);return;}
      // Wait for the content modal to finish closing: showing the second modal while
      // the first is still animating out leaves Bootstrap's backdrop behind.
      el('sm-msg-modal').addEventListener('hidden.bs.modal',function once(){
        el('sm-msg-modal').removeEventListener('hidden.bs.modal',once);
        showList(r);
      });
      msgModal.hide();
    });
    ['sm-list-kind','sm-list-scope','sm-list-cond','sm-list-match'].forEach(function(id){el(id).addEventListener('change',listRender);});
    el('sm-list-save').addEventListener('click',function(){listSave(this);});
    el('sm-rejected-notify-form').addEventListener('submit',function(e){e.preventDefault();save('rejected_notify_save',{value:el('sm-rejected-notify').value},this.querySelector('button'),function(d){if(d&&d.notify!==undefined)el('sm-rejected-notify').value=d.notify;});});
    el('sm-outbound-search').addEventListener('input',renderOutbound);el('sm-outbound-refresh').addEventListener('click',loadOutbound);
    el('sm-custom-refresh').addEventListener('click',loadCustomizations);
    el('sm-update-refresh').addEventListener('click',function(){loadUpdate();});
    el('sm-geo-refresh').addEventListener('click',function(){geoDirty=false;loadGeo();});
    el('sm-geo-enabled').addEventListener('change',function(){if(geoDraft){geoDraft.enabled=this.checked;geoMarkDirty();}});
    el('sm-geo-add').addEventListener('click',function(){if(!geoDraft)return;var r=geoResolve(el('sm-geo-add-cc').value);
      if(!r.cc){geoHint('sm-geo-add-cc','sm-geo-add-hint');el('sm-geo-add-cc').focus();return;}
      if(geoDraft.countries.indexOf(r.cc)>=0){el('sm-geo-add-hint').textContent=ccName(r.cc)+' 已經在常駐清單裡';el('sm-geo-add-hint').className='small mb-3 text-muted';return;}
      geoDraft.countries.push(r.cc);el('sm-geo-add-cc').value='';el('sm-geo-add-hint').textContent='';geoMarkDirty();});
    el('sm-geo-add-cc').addEventListener('input',function(){geoHint('sm-geo-add-cc','sm-geo-add-hint');});
    el('sm-geo-add-cc').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();el('sm-geo-add').click();}});
    el('sm-geo-temp-cc').addEventListener('input',function(){geoHint('sm-geo-temp-cc','sm-geo-temp-hint');});
    el('sm-geo-temp-cc').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();el('sm-geo-temp-add').click();}});
    el('sm-geo-temp-add').addEventListener('click',function(){if(!geoDraft)return;var r=geoResolve(el('sm-geo-temp-cc').value),days=parseInt(el('sm-geo-temp-days').value,10)||7;
      if(!r.cc){geoHint('sm-geo-temp-cc','sm-geo-temp-hint');el('sm-geo-temp-cc').focus();return;}var cc=r.cc;el('sm-geo-temp-cc').value='';el('sm-geo-temp-hint').textContent='';
      geoDraft.temporary=geoDraft.temporary.filter(function(e){return e.cc!==cc;});geoDraft.temporary.push({cc:cc,until:Math.floor(Date.now()/1000)+days*86400,note:el('sm-geo-temp-note').value.trim().slice(0,60)});el('sm-geo-temp-note').value='';geoMarkDirty();});
    el('sm-geo-form').addEventListener('submit',function(e){e.preventDefault();submitGeo();});
    el('sm-update-key').addEventListener('change',renderUpdateLog);
    el('sm-update-follow').addEventListener('change',function(){if(this.checked){var p=el('sm-update-log');p.scrollTop=p.scrollHeight;}});
    setInterval(function(){if(updatePolling)updateElapsed(true,null);},1000);
    el('sm-update-form').addEventListener('submit',function(e){
      e.preventDefault();
      var pass=el('sm-update-pass').value;
      if(!pass){message('請輸入更新密碼。',true);return;}
      if(!window.confirm('確定現在更新 Mailcow？\n\n會執行官方 update.sh 並重新套用本機自訂設定。\n過程中網頁與郵件服務會短暫中斷，請避開尖峰時段。'))return;
      var btn=this.querySelector('button');btn.disabled=true;
      SM.request('update_request',{passphrase:pass}).done(function(r){
        el('sm-update-pass').value='';
        message(r.message||'已送出更新請求。',false);
        pollUpdate();
      }).fail(function(xhr,status){cardFail('sm-update-status',xhr,status);btn.disabled=false;});
    });
    el('sm-nas-form').addEventListener('submit',function(e){
      e.preventDefault();
      // No passphrase: the confirmation below is the only gate, because the interruption
      // is the real cost and the destination cannot be changed from here.
      if(!window.confirm('確定現在備份到 NAS？\n\n備份期間 dovecot／postfix／redis／rspamd 會短暫停止，郵件收發會中斷。\n請避開尖峰時段。'))return;
      var btn=this.querySelector('button');btn.disabled=true;
      SM.request('backup_request',{}).done(function(r){
        message(r.message||'已送出備份請求。',false);
        pollNas();
      }).fail(function(xhr,status){cardFail('sm-nas-status',xhr,status);btn.disabled=false;});
    });
    el('sm-nas-notify-form').addEventListener('submit',function(e){e.preventDefault();save('backup_notify_save',{value:el('sm-nas-notify').value},this.querySelector('button'),function(d){if(d&&d.notify!==undefined)el('sm-nas-notify').value=d.notify;});});
    el('sm-nassetup-refresh').addEventListener('click',function(){loadNasSetup();});
    el('sm-nassetup-form').addEventListener('submit',function(e){
      e.preventDefault();
      var v={nas_host:el('sm-nassetup-host').value.trim(),
             nas_share:el('sm-nassetup-share').value.trim(),
             nas_path:el('sm-nassetup-path').value.trim(),
             nas_user:el('sm-nassetup-user').value.trim(),
             nas_domain:el('sm-nassetup-domain').value.trim(),
             nas_pass:el('sm-nassetup-pass').value,
             nas_vers:el('sm-nassetup-vers').value,
             keep:el('sm-nassetup-keep').value.trim(),
             passphrase:el('sm-nassetup-passphrase').value};
      if(!v.nas_host||!v.nas_share||!v.nas_user){message('伺服器、分享名稱與使用者名稱都要填。',true);return;}
      if(!v.nas_pass){message('請輸入 NAS 密碼。',true);return;}
      if(!v.passphrase){message('請輸入更新密碼。',true);return;}
      if(!window.confirm('確定儲存這組 NAS 連線設定？\n\n主機會實際掛載測試，並在第一次設定時產生備份加密金鑰。\n金鑰不會顯示在網頁上，請設定完成後到主機取出保管。'))return;
      var btn=this.querySelector('button[type="submit"]');btn.disabled=true;
      SM.request('nas_setup_request',v).done(function(r){
        el('sm-nassetup-pass').value='';el('sm-nassetup-passphrase').value='';
        message(r.message||'已送出設定請求。',false);
        pollNasSetup();
      }).fail(function(xhr,status){cardFail('sm-nassetup-status',xhr,status);btn.disabled=false;});
    });
    el('sm-host-refresh').addEventListener('click',function(){loadHost();});
    el('sm-host-form').addEventListener('submit',function(e){
      e.preventDefault();
      submitHost('apply','確定現在套用主機更新？\n\n會升級 docker.io／containerd／runc，容器執行環境將重啟，郵件收發短暫中斷。\n請避開尖峰時段。');
    });
    el('sm-host-reboot-btn').addEventListener('click',function(){
      submitHost('reboot','確定現在重新開機？\n\n整台主機會立即重開，期間郵件服務完全中斷（約 2～3 分鐘）。\n開機後容器會自動回復（重啟策略為 always）。');
    });
    el('sm-nas-refresh').addEventListener('click',function(){loadNas();});
    el('sm-restore-refresh').addEventListener('click',function(){loadRestore();loadNas();});
    el('sm-restore-form').addEventListener('submit',function(e){
      e.preventDefault();
      var name=el('sm-restore-backup').value;
      var confirmText=el('sm-restore-confirm').value.trim();
      var pass=el('sm-restore-pass').value;
      var comps=Array.prototype.slice.call(el('sm-restore-components').querySelectorAll('input:checked')).map(function(i){return i.value;});
      if(!name){message('請選擇要還原的備份。',true);return;}
      if(!comps.length){message('請至少選擇一個要還原的元件。',true);return;}
      if(confirmText!==name){message('確認欄位必須與備份名稱完全相同。',true);return;}
      if(!pass){message('請輸入更新密碼。',true);return;}
      if(!window.confirm('確定要還原 '+name+' 嗎？\n\n將覆蓋：'+comps.join('、')+'\n\n這會覆蓋線上資料且無法復原，期間服務會中斷。\n還原前會自動快照目前的 mysql 與 redis。'))return;
      var btn=this.querySelector('button');btn.disabled=true;
      SM.request('restore_request',{backup:name,components:comps,confirm:confirmText,passphrase:pass}).done(function(r){
        el('sm-restore-pass').value='';el('sm-restore-confirm').value='';
        message(r.message||'已送出還原請求。',false);
        pollRestore();
      }).fail(function(xhr,status){cardFail('sm-restore-status',xhr,status);btn.disabled=false;});
    });

    el('sm-outbound-notify-form').addEventListener('submit',function(e){e.preventDefault();save('outbound_notify_save',{value:el('sm-outbound-notify').value},this.querySelector('button'),function(d){if(d&&d.notify!==undefined)el('sm-outbound-notify').value=d.notify;});});
    openPanel(window.location.hash.indexOf('#sm-')===0?window.location.hash.substring(4):'overview');refreshAll();
  });
})(jQuery);

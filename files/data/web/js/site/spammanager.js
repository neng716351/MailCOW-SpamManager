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
  function mapEffect(file) {
    if (file.indexOf('global_rcpt_white') === 0) return '比對收件地址，命中時可直接接受，會影響後續評分結果。';
    if (file.indexOf('global_rcpt_black') === 0) return '比對收件地址，命中時可直接拒收。';
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
    el('sm-map-content').value = m.content; el('sm-map-effect').textContent = mapEffect(mapFile); el('sm-map-form').querySelector('button[type=submit]').disabled = false; mapCount();
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
  function rejectedStatus(){
    el('sm-rejected-status').textContent='共 '+rejectedRows.length+' 封被留存的拒收郵件。只含收件人為本機信箱且已留存者；SMTP 連線階段拒收與往外寄被拒不會出現在此。';
  }
  function renderRejected(){
    var term=el('sm-rejected-search').value.toLowerCase(),tbody=el('sm-rejected-rows');tbody.replaceChildren();
    var rows=rejectedRows.filter(function(r){return [r.sender,r.rcpt,r.subject].join(' ').toLowerCase().indexOf(term)>=0;});
    if(!rows.length){var tr=node('tr'),td=node('td',rejectedRows.length?'沒有符合搜尋的郵件。':'目前沒有被留存的拒收郵件。');td.colSpan=4;td.className='small text-muted';tr.appendChild(td);tbody.appendChild(tr);return;}
    rows.forEach(function(r){
      var tr=node('tr');
      tr.appendChild(node('td',r.created?new Date(r.created*1000).toLocaleString('zh-TW',{hour12:false}):'—','small'));
      var td=node('td');td.appendChild(node('div',(r.sender||'（空寄件者）')+' → '+(r.rcpt||''),'small'));
      var subject=node('div',r.subject||'（無主旨）','small text-muted sm-subject');subject.title=r.subject||'';td.appendChild(subject);
      if(r.virus){var vb=node('span','病毒命中','badge bg-danger');td.appendChild(vb);}
      tr.appendChild(td);
      tr.appendChild(node('td',Number(r.score).toFixed(2)));
      td=node('td','',' sm-actions');var b=node('button','放行','btn btn-sm btn-outline-primary');b.type='button';
      b.addEventListener('click',function(){releaseRejected(r,b);});td.appendChild(b);tr.appendChild(td);
      tbody.appendChild(tr);
    });
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
    el('sm-rejected-status').textContent='正在讀取被留存的拒收郵件…';
    $.ajax({url:api,type:'GET',dataType:'json',timeout:20000,data:{op:'rejected'}}).done(function(r){rejectedLoaded=true;rejectedRows=r.data.rows||[];if(r.data.notify!==undefined)el('sm-rejected-notify').value=r.data.notify;rejectedStatus();renderRejected();}).fail(function(xhr,status){el('sm-rejected-status').textContent='清單讀取失敗，可按更新重試。';failure(xhr,status);});
  }
  var updatePolling=false;
  function renderUpdate(d){
    var host=el('sm-update-status'),states={idle:['尚未執行過更新','text-muted'],running:['更新進行中…','text-warning'],done:['上次更新完成','text-success'],error:['上次更新有問題','text-danger'],rejected:['上次請求被拒絕','text-danger']};
    if(!d.available){host.textContent=d.message||'尚未啟用網頁更新。';host.className='small text-muted mb-2';el('sm-update-form').querySelector('button').disabled=true;el('sm-update-pass').disabled=true;return;}
    var s=states[d.state]||states.idle,when=d.updated?('（'+new Date(d.updated*1000).toLocaleString('zh-TW',{hour12:false})+'）'):'';
    host.textContent=s[0]+when+(d.message?('：'+d.message):'');
    host.className='small mb-2 '+s[1];
    var busy=d.state==='running'||d.pending;
    el('sm-update-form').querySelector('button').disabled=busy;
    el('sm-update-pass').disabled=busy;
    var log=el('sm-update-log');
    if(d.log){log.hidden=false;log.textContent=d.log;log.scrollTop=log.scrollHeight;}else{log.hidden=true;}
    if(busy&&!updatePolling)pollUpdate();
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
    el('sm-refresh').addEventListener('click',function(){if(Object.keys(drafts).length || (mapFile && SM.state && el('sm-map-content').value!==SM.state.maps[mapFile].content)){if(!window.confirm('重新讀取會捨棄尚未儲存的權重與名單內容，是否繼續？'))return;}loadState();});
    el('sm-actions-form').addEventListener('submit',function(e){e.preventDefault();if(!SM.state || !SM.state.actions)return;save('save_actions',{values:{greylist:el('sm-grey').value,'add header':el('sm-tag').value,reject:el('sm-reject').value},baseline:SM.state.actions},this.querySelector('button'),function(d){SM.state.actions=d.actions;actions();summary();});});
    ['sm-grey','sm-tag','sm-reject'].forEach(function(id){el(id).addEventListener('input',simulate);});
    el('sm-symbol-search').addEventListener('input',function(){page=0;symbols();});el('sm-symbol-prev').addEventListener('click',function(){page--;symbols();});el('sm-symbol-next').addEventListener('click',function(){page++;symbols();});
    el('sm-sim-clear').addEventListener('click',function(){selected={};symbols();simulate();});
    el('sm-save-symbols').addEventListener('click',function(){var originals={};SM.state.symbols.forEach(function(s){originals[s.name]=s.weight;});var changes=Object.keys(drafts).map(function(k){return {name:k,value:drafts[k],baseline:originals[k]};});save('save_symbols',{changes:changes},this,function(){changes.forEach(function(c){SM.state.symbols.find(function(s){return s.name===c.name;}).weight=Number(c.value);});drafts={};symbols();simulate();});});
    el('sm-map-select').addEventListener('change',function(){if(mapFile && el('sm-map-content').value!==SM.state.maps[mapFile].content && !window.confirm('切換名單會捨棄未儲存內容，是否繼續？')){this.value=mapFile;return;}showMap();});
    el('sm-map-content').addEventListener('input',mapCount);
    el('sm-map-insert').addEventListener('click',function(){var address=el('sm-map-address').value.trim();if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)){message('請輸入完整郵件地址。',true);return;}var escaped=address.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/\//g,'\\/');var area=el('sm-map-content');area.value=area.value.replace(/\s*$/,'')+'\n/^'+escaped+'$/i\n';mapCount();});
    el('sm-map-form').addEventListener('submit',function(e){e.preventDefault();if(!SM.state || !SM.state.maps[mapFile])return;var file=mapFile;save('save_map',{file:file,content:el('sm-map-content').value,baseline:SM.state.maps[file].hash},this.querySelector('button[type=submit]'),function(d){SM.state.maps[file]=d.map;loadMapOptions();summary();});});
    el('sm-scope').addEventListener('change',scope);
    el('sm-policy-form').addEventListener('submit',function(e){e.preventDefault();save('policy_add',{object:el('sm-scope').value.trim(),kind:el('sm-policy-kind').value,value:el('sm-policy-value').value},this.querySelector('button'),refreshPolicies);});
    function saveScope(reset,button){var target=el('sm-scope').value.trim();save('scope_score',{object:target,tag:el('sm-scope-tag').value,reject:el('sm-scope-reject').value,reset:reset,baseline:(SM.state.scope_baselines||{})[target]},button,refreshPolicies);}
    el('sm-scope-form').addEventListener('submit',function(e){e.preventDefault();saveScope(false,this.querySelector('button'));});el('sm-scope-reset').addEventListener('click',function(){saveScope(true,this);});
    el('sm-history-search').addEventListener('input',renderHistory);el('sm-history-refresh').addEventListener('click',loadHistory);
    el('sm-rejected-search').addEventListener('input',renderRejected);el('sm-rejected-refresh').addEventListener('click',loadRejected);
    el('sm-rejected-notify-form').addEventListener('submit',function(e){e.preventDefault();save('rejected_notify_save',{value:el('sm-rejected-notify').value},this.querySelector('button'),function(d){if(d&&d.notify!==undefined)el('sm-rejected-notify').value=d.notify;});});
    el('sm-outbound-search').addEventListener('input',renderOutbound);el('sm-outbound-refresh').addEventListener('click',loadOutbound);
    el('sm-custom-refresh').addEventListener('click',loadCustomizations);
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
      }).fail(function(xhr,status){failure(xhr,status);btn.disabled=false;});
    });
    el('sm-outbound-notify-form').addEventListener('submit',function(e){e.preventDefault();save('outbound_notify_save',{value:el('sm-outbound-notify').value},this.querySelector('button'),function(d){if(d&&d.notify!==undefined)el('sm-outbound-notify').value=d.notify;});});
    openPanel(window.location.hash.indexOf('#sm-')===0?window.location.hash.substring(4):'overview');loadState();loadCustomizations();loadUpdate();
  });
})(jQuery);

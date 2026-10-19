jQuery(function ($) {
  'use strict';
  var form = document.getElementById('impersonation-form');
  if (!form) return;
  // This AJAX form owns its submit state; remove the native page-submit hook.
  $(form).off('submit');
  var select = document.getElementById('impersonation-rule');
  if ($(select).data('selectpicker')) $(select).selectpicker('destroy');
  select.hidden = true;
  select.style.display = 'none';
  var name = document.getElementById('impersonation-name');
  var emails = document.getElementById('impersonation-emails');
  var active = document.getElementById('impersonation-active');
  var preview = document.getElementById('impersonation-preview');
  var result = document.getElementById('impersonation-result');
  var save = document.getElementById('impersonation-save');
  function addresses() { return emails.value.trim().split(/[\s,;]+/).filter(Boolean); }
  function update() {
    preview.textContent = (active.checked ? '啟用後：' : '儲存為停用：') + '顯示名稱包含「' + (name.value.trim() || '請輸入姓名') + '」，且寄件信箱不是「' + (addresses().join('、') || '請輸入允許信箱') + '」時，標記為垃圾郵件。';
  }
  function load() {
    var option = select.options[select.selectedIndex];
    name.value = option.getAttribute('data-name') || '';
    emails.value = option.getAttribute('data-emails') || '';
    active.checked = !select.value || option.getAttribute('data-active') === '1';
    result.textContent = '';
    document.getElementById('impersonation-delete').hidden = !select.value;
    document.getElementById('impersonation-title').textContent = select.value ? '編輯規則：' + name.value : '新增規則';
    document.querySelectorAll('[data-sm-row]').forEach(function (row) {
      row.classList.toggle('table-active', row.getAttribute('data-sm-row') === select.value);
    });
    update();
  }
  select.addEventListener('change', load);
  window.SpamManager.onRulesChange = load;
  document.getElementById('spam-manager').addEventListener('click', function (event) {
    var button = event.target.closest('[data-sm-rule]');
    if (!button) return;
    select.value = button.getAttribute('data-sm-rule'); load(); name.focus({preventScroll: true});
  });
  document.getElementById('impersonation-delete').addEventListener('click', function () {
    if (!select.value || !window.confirm('刪除「' + name.value + '」防冒名規則？')) return;
    var button = this; button.disabled = true;
    window.SpamManager.request('impersonation_delete', {id: select.value, baseline: select.options[select.selectedIndex].getAttribute('data-hash')})
      .done(function (r) { window.SpamManager.refreshRules(r.data.rules, ''); result.className = 'alert alert-success'; result.textContent = r.message; })
      .fail(function (xhr) { result.className = 'alert alert-danger'; result.textContent = (xhr.responseJSON || {}).message || '刪除失敗，請重試。'; })
      .always(function () { button.disabled = false; });
  });
  form.addEventListener('input', update);
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (save.disabled) return;
    if (!form.reportValidity()) return;
    var list = addresses();
    if (!list.length || list.length > 20 || list.some(function (s) { return !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); })) {
      result.className = 'alert alert-danger'; result.textContent = '請輸入 1 至 20 個有效信箱。'; return;
    }
    var token = document.getElementById('spammanager-csrf').value;
    if (!token) {
      result.className = 'alert alert-danger'; result.textContent = '登入驗證已失效，請重新登入後再儲存。'; return;
    }
    save.disabled = true;
    save.textContent = '正在儲存…';
    result.className = 'alert alert-info'; result.textContent = '正在儲存…';
    var data = {id: select.value, impersonation_name: name.value.trim(), impersonation_emails: list, active: active.checked ? 1 : 0};
    if (select.value) data.baseline = select.options[select.selectedIndex].getAttribute('data-hash');
    window.SpamManager.request('impersonation_save', data)
      .done(function (response) {
        if (!response.ok) { result.className = 'alert alert-danger'; result.textContent = response.message || '儲存失敗。'; return; }
        window.SpamManager.refreshRules(response.data.rules, response.data.id);
        result.className = 'alert alert-success'; result.textContent = response.message;
      })
      .fail(function (xhr, status) { result.className = 'alert alert-danger'; result.textContent = status === 'timeout' ? '回應逾時，請重新讀取設定確認是否已儲存，避免重複新增。' : ((xhr.responseJSON || {}).message || '儲存失敗，請重試。'); })
      .always(function () { save.disabled = false; save.textContent = '儲存規則'; save.removeAttribute('data-submitted'); });
  });
  if (select.options.length > 1) select.selectedIndex = 1;
  load();
});

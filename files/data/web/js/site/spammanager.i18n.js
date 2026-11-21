/*
 * Spam Manager UI translation (browser side). Loaded before spammanager.js.
 *
 * The UI is written in Traditional Chinese and that text is the translation key. This
 * file translates the page in place -- on load and whenever the page re-renders -- so the
 * application code needs no per-language branches.
 *
 * A text is translated only when it is made ENTIRELY of known fragments plus non-Han
 * characters. Mail data (a Chinese subject, a sender's name) contains Han text no
 * fragment covers, so it is left exactly as it is. <pre>, <textarea>, form values and
 * anything inside [data-sm-raw] are never touched.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('sm-i18n');
  var cfg = {meta: {lang: 'zh-tw', cjk: true}, strings: {}};
  try { if (cfgEl) cfg = JSON.parse(cfgEl.textContent || '{}'); } catch (e) {}
  var meta = cfg.meta || {}, strings = cfg.strings || {};
  var lang = (meta.lang || document.documentElement.lang || 'zh-tw').toLowerCase();
  // Exposed for spammanager.js: dates, Intl region names, sorting.
  window.SM_I18N = {
    lang: lang,
    zh: lang.indexOf('zh') === 0,
    intl: lang === 'zh-tw' ? 'zh-TW' : (lang === 'zh-cn' ? 'zh-CN' : lang.replace(/-([a-z]+)$/, function (m, r) { return '-' + r.toUpperCase(); })),
    t: translate
  };
  var keys = Object.keys(strings);
  if (!keys.length) return;                       // source language: nothing to do

  var HAN = /[㐀-鿿豈-﫿]/;
  var PUNCT = {'，': ', ', '。': '. ', '：': ': ', '；': '; ', '（': ' (', '）': ')', '「': '"', '」': '"', '、': ', ',
    '？': '?', '！': '!', '／': '/', '～': '~', '．': '·', '［': '[', '］': ']', '　': ' '};
  var cjk = !!meta.cjk;
  // Plain fragments, indexed by first character, longest first. Keys containing {n} are
  // templates whose {n} matches a number, so word order can differ per language
  // ("第 {n} 行" -> "Line {n}", "共 {n} 行" -> "{n} lines").
  var index = {}, tpl = {};
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  keys.forEach(function (k) {
    if (!k) return;
    if (k.indexOf('{n}') >= 0) {
      if (k.charAt(0) === '{') return;              // must start with literal text
      var re = new RegExp(k.split('{n}').map(esc).join('([0-9][0-9,.]*)'), 'y');
      (tpl[k.charAt(0)] = tpl[k.charAt(0)] || []).push({re: re, tr: strings[k], len: k.length});
    } else (index[k.charAt(0)] = index[k.charAt(0)] || []).push(k);
  });
  Object.keys(index).forEach(function (c) { index[c].sort(function (a, b) { return b.length - a.length; }); });
  Object.keys(tpl).forEach(function (c) { tpl[c].sort(function (a, b) { return b.len - a.len; }); });

  function translate(s) {
    if (typeof s !== 'string' || !HAN.test(s)) return s;
    var trim = s.trim();
    if (Object.prototype.hasOwnProperty.call(strings, trim)) return s.replace(trim, strings[trim]);
    var out = '', i = 0, n = s.length;
    while (i < n) {
      var tl = tpl[s.charAt(i)], list = index[s.charAt(i)], hit = false;
      if (tl) for (var q = 0; q < tl.length; q++) {
        tl[q].re.lastIndex = i;
        var m = tl[q].re.exec(s);
        if (m) { var g = 1; out += tl[q].tr.replace(/\{n\}/g, function () { return m[g++] || ''; }); i = tl[q].re.lastIndex; hit = true; break; }
      }
      if (hit) continue;
      if (list) for (var j = 0; j < list.length; j++) {
        var k = list[j];
        if (s.substr(i, k.length) === k) { out += strings[k]; i += k.length; hit = true; break; }
      }
      if (hit) continue;
      var c = s.charAt(i);
      if (HAN.test(c)) return s;                    // not ours: leave the whole text alone
      out += (!cjk && PUNCT[c]) ? PUNCT[c] : c;
      i++;
    }
    return tidy(s, out);
  }
  // Keep the original's outer whitespace; for non-CJK scripts drop the stray spaces that
  // joining fragments leaves ("x )", "x 's").
  function tidy(src, out) {
    var lead = src.match(/^\s*/)[0], trail = src.match(/\s*$/)[0];
    out = out.replace(/ {2,}/g, ' ').trim();
    if (!cjk) out = out.replace(/ +([)\],.;:!?])/g, '$1').replace(/ 's /g, "'s ").replace(/\( +/g, '(');
    return lead + out + trail;
  }
  function translateLines(s) { return typeof s === 'string' ? s.split('\n').map(translate).join('\n') : s; }

  var SKIP = {PRE: 1, TEXTAREA: 1, SCRIPT: 1, STYLE: 1, CODE: 1};
  var ATTRS = ['placeholder', 'title', 'aria-label', 'alt'];
  function skipped(el) {
    for (; el && el.nodeType === 1; el = el.parentNode) {
      if (SKIP[el.tagName] || el.hasAttribute('data-sm-raw')) return true;
      if (el.id === 'spam-manager') return false;
    }
    return false;
  }
  function doText(node) {
    if (!HAN.test(node.data) || skipped(node.parentNode)) return;
    var t = translate(node.data);
    if (t !== node.data) node.data = t;
  }
  function doAttrs(el) {
    if (el.nodeType !== 1 || skipped(el)) return;
    for (var i = 0; i < ATTRS.length; i++) {
      var v = el.getAttribute(ATTRS[i]);
      if (v && HAN.test(v)) { var t = translate(v); if (t !== v) el.setAttribute(ATTRS[i], t); }
    }
    if (el.tagName === 'INPUT' && /^(button|submit|reset)$/i.test(el.type) && HAN.test(el.value)) el.value = translate(el.value);
  }
  function walk(root) {
    if (root.nodeType === 3) { doText(root); return; }
    if (root.nodeType !== 1 || SKIP[root.tagName]) return;
    doAttrs(root);
    var w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, null), n;
    while ((n = w.nextNode())) { if (n.nodeType === 3) doText(n); else doAttrs(n); }
  }

  // Dialogs bypass the DOM, so translate them on the way out.
  var nativeConfirm = window.confirm, nativeAlert = window.alert, nativePrompt = window.prompt;
  window.confirm = function (m) { return nativeConfirm.call(window, translateLines(m)); };
  window.alert = function (m) { return nativeAlert.call(window, translateLines(m)); };
  window.prompt = function (m, d) { return nativePrompt.call(window, translateLines(m), d); };

  function start() {
    var root = document.getElementById('spam-manager');
    if (!root) return;
    if (meta.notice) {
      var note = document.createElement('div');
      note.className = 'alert alert-secondary small py-1 px-2 mb-2';
      note.setAttribute('data-sm-raw', '');
      note.textContent = meta.notice;
      root.insertBefore(note, root.firstChild);
    }
    walk(root);
    // spammanager.js re-renders tables and status lines constantly; follow it.
    new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'characterData') doText(m.target);
        else if (m.type === 'attributes') doAttrs(m.target);
        else for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]);
      }
    }).observe(root, {subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS.concat(['value'])});
    // Modals are appended outside #spam-manager by Bootstrap? They live inside it here,
    // but the page title lives outside: translate it once.
    document.title = translate(document.title);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();

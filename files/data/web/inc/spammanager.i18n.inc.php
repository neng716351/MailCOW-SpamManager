<?php
/**
 * Spam Manager UI translation.
 *
 * The UI is written in Traditional Chinese, which is also the translation key: each
 * language file maps a zh-TW fragment to its translation. Text is translated at render
 * time (in the browser for the admin page, here for qpreview.php), so the program logic
 * never changes per language.
 *
 * A text is translated only when it consists ENTIRELY of known fragments plus non-Han
 * characters (digits, Latin, punctuation). Anything else -- a Chinese mail subject, a
 * sender name -- contains Han characters no fragment covers and is left untouched, so
 * mail data is never "translated" by accident.
 */

/**
 * The mail domain of THIS install, for examples shown on the page. Taken from the
 * first active mail domain, falling back to MAILCOW_HOSTNAME without its first label
 * (mail.example.com -> example.com). Nothing site-specific is stored in the plugin.
 */
if (!function_exists('sm_install_domain')) {
function sm_install_domain(): string {
  global $pdo;
  try {
    $d = $pdo->query("SELECT `domain` FROM `domain` WHERE `active` = '1' ORDER BY `created` LIMIT 1")->fetchColumn();
    if (is_string($d) && $d !== '') return $d;
  } catch (Throwable $e) {}
  $h = strtolower((string)getenv('MAILCOW_HOSTNAME'));
  $parts = explode('.', $h);
  return count($parts) > 2 ? implode('.', array_slice($parts, 1)) : ($h !== '' ? $h : 'example.com');
}
}

const SM_I18N_DIR = __DIR__ . '/spammanager-i18n';
const SM_I18N_SOURCE = 'zh-tw';

function sm_i18n_locale(): string {
  $l = strtolower((string)($_SESSION['mailcow_locale'] ?? ($_COOKIE['mailcow_locale'] ?? 'en-gb')));
  if (!preg_match('/^[a-z]{2}-[a-z]{2}$/', $l)) $l = 'en-gb';
  if ($l === SM_I18N_SOURCE) return $l;
  if (is_file(SM_I18N_DIR . "/$l.json")) return $l;
  return 'en-gb';
}

/** @return array{meta: array, strings: array<string,string>} */
function sm_i18n_bundle(?string $locale = null): array {
  static $cache = [];
  $locale = $locale ?? sm_i18n_locale();
  if (isset($cache[$locale])) return $cache[$locale];
  $empty = ['meta' => ['lang' => SM_I18N_SOURCE, 'cjk' => true, 'machine' => false, 'notice' => ''], 'strings' => []];
  if ($locale === SM_I18N_SOURCE) return $cache[$locale] = $empty;
  $raw = @file_get_contents(SM_I18N_DIR . "/$locale.json");
  $d = is_string($raw) ? json_decode($raw, true) : null;
  if (!is_array($d) || !is_array($d['strings'] ?? null)) return $cache[$locale] = $empty;
  $meta = array_merge($empty['meta'], is_array($d['meta'] ?? null) ? $d['meta'] : [], ['lang' => $locale]);
  return $cache[$locale] = ['meta' => $meta, 'strings' => array_filter($d['strings'], 'is_string')];
}

/** JSON for the page: <script type="application/json" id="sm-i18n">. */
function sm_i18n_payload(): string {
  $b = sm_i18n_bundle();
  return json_encode($b, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
}

const SM_I18N_PUNCT = ['，' => ', ', '。' => '. ', '：' => ': ', '；' => '; ', '（' => ' (', '）' => ')', '「' => '"', '」' => '"',
  '、' => ', ', '？' => '?', '！' => '!', '／' => '/', '～' => '~', '．' => '·', '［' => '[', '］' => ']', '　' => ' '];

/** Translate one text, or return it unchanged when it is not fully covered. */
function sm_i18n_text(string $s): string {
  static $index = null, $tpl = [], $strings = null, $cjk = true;
  if ($index === null) {
    $b = sm_i18n_bundle(); $strings = $b['strings']; $cjk = !empty($b['meta']['cjk']); $index = [];
    foreach (array_keys($strings) as $k) {
      $k = (string)$k; if ($k === '') continue;
      $first = mb_substr($k, 0, 1);
      if (str_contains($k, '{n}')) {
        // Templates: {n} matches a number, so word order can differ per language.
        if ($first === '{') continue;
        $re = '/\G' . implode('([0-9][0-9,.]*)', array_map(fn($p) => preg_quote($p, '/'), explode('{n}', $k))) . '/u';
        $tpl[$first][] = ['re' => $re, 'tr' => $strings[$k], 'len' => mb_strlen($k)];
      } else $index[$first][] = $k;
    }
    foreach ($index as &$list) usort($list, fn($a, $b) => strlen($b) <=> strlen($a));
    foreach ($tpl as &$list) usort($list, fn($a, $b) => $b['len'] <=> $a['len']);
    unset($list);
  }
  if (!$strings || !preg_match('/\p{Han}/u', $s)) return $s;
  $trim = trim($s);
  if (isset($strings[$trim])) return str_replace($trim, $strings[$trim], $s);
  $out = ''; $o = 0; $len = strlen($s);
  while ($o < $len) {
    if (!preg_match('/\G./us', $s, $cm, 0, $o)) break;
    $c = $cm[0]; $hit = false;
    foreach ($tpl[$c] ?? [] as $t) {
      if (preg_match($t['re'], $s, $m, 0, $o)) {
        $g = 1; $out .= preg_replace_callback('/\{n\}/', function () use (&$g, $m) { return $m[$g++] ?? ''; }, $t['tr']);
        $o += strlen($m[0]); $hit = true; break;
      }
    }
    if (!$hit) foreach ($index[$c] ?? [] as $k) {
      if (substr_compare($s, $k, $o, strlen($k)) === 0) { $out .= $strings[$k]; $o += strlen($k); $hit = true; break; }
    }
    if ($hit) continue;
    if (preg_match('/\p{Han}/u', $c)) return $s;           // not ours: leave the whole text alone
    $out .= (!$cjk && isset(SM_I18N_PUNCT[$c])) ? SM_I18N_PUNCT[$c] : $c;
    $o += strlen($c);
  }
  // Keep the original's outer whitespace; for non-CJK scripts drop the stray spaces that
  // joining fragments leaves ("x )", "x 's").
  preg_match('/^\s*/u', $s, $l); preg_match('/\s*$/u', $s, $r);
  $out = trim(preg_replace('/ {2,}/', ' ', $out));
  if (!$cjk) $out = preg_replace(['/ +([)\],.;:!?])/u', "/ 's /u", '/\( +/u'], ['$1', "'s ", '('], $out);
  return $l[0] . $out . $r[0];
}

/**
 * Translate a whole HTML page (qpreview.php). The sandboxed iframe's srcdoc (the mail
 * itself) is never touched.
 */
function sm_i18n_html(string $html): string {
  if (sm_i18n_locale() === SM_I18N_SOURCE || !preg_match('/\p{Han}/u', $html)) return $html;
  $doc = new DOMDocument();
  $prev = libxml_use_internal_errors(true);
  $ok = $doc->loadHTML('<?xml encoding="utf-8"?>' . $html, LIBXML_NOERROR | LIBXML_NOWARNING);
  libxml_clear_errors(); libxml_use_internal_errors($prev);
  if (!$ok) return $html;
  $xp = new DOMXPath($doc);
  // Mail data is marked data-sm-raw and skipped outright (a subject may equal a UI word);
  // the sandboxed srcdoc is an attribute and never read.
  foreach ($xp->query('//text()[not(ancestor::script) and not(ancestor::style) and not(ancestor-or-self::*[@data-sm-raw])]') as $t) {
    $t->nodeValue = sm_i18n_text($t->nodeValue);
  }
  foreach ($xp->query('//@title | //@placeholder | //@aria-label') as $a) $a->value = sm_i18n_text($a->value);
  foreach ($xp->query('//html') as $h) $h->setAttribute('lang', sm_i18n_locale());
  $out = $doc->saveHTML();
  return '<!doctype html>' . preg_replace('/^<!DOCTYPE[^>]*>\s*|<\?xml encoding="utf-8"\?>/i', '', $out);
}

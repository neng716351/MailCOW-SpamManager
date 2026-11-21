<?php
// Local extension: read-only quarantine preview; never render message HTML.
header('Cache-Control: no-store, private');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
$qp_show_images = (($_GET['images'] ?? '') === '1');
// The message body renders inside a sandboxed srcdoc iframe, so the parent policy is what
// constrains it. Images are data: only unless the viewer explicitly opted in this view.
$qp_img_src = $qp_show_images ? "img-src data: https: http:" : "img-src data:";
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; {$qp_img_src}; frame-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    header('Allow: GET');
    http_response_code(405);
    exit('Method not allowed');
}
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/spammanager.i18n.inc.php';
// Translate the page's own wording into the viewer's mailcow language. Mail data sits in
// elements marked data-sm-raw and in the sandboxed srcdoc, which sm_i18n_html() never touches.
ob_start('sm_i18n_html');

// Local addition 2026-11-13: render the message's ORIGINAL HTML layout instead of only a
// text conversion. The HTML is attacker-controlled, so it is rebuilt from a whitelist
// with DOMDocument, then shown inside a sandboxed, scriptless iframe. Three rules:
//   - no scripts, no plugins, no forms, no frames, no <base>, no meta refresh;
//   - links are rendered DEAD and annotated with their real destination, because the
//     whole point of reading a phishing mail is to see where it actually pointed;
//   - remote images are off by default (loading one tells the sender the mailbox is
//     live and that staff are reading it); inline cid: images become data: URIs so
//     genuine layout still survives. ?images=1 opts in, deliberately, per view.

const QP_ALLOWED_TAGS = [
    'a','abbr','b','blockquote','body','br','caption','center','cite','code','col','colgroup',
    'dd','div','dl','dt','em','figcaption','figure','font','h1','h2','h3','h4','h5','h6','hr',
    'i','img','li','ol','p','pre','q','s','small','span','strike','strong','sub','sup','table',
    'tbody','td','tfoot','th','thead','tr','u','ul','wbr',
];
// style is allowed: the iframe CSP forbids remote loads, so url() cannot phone home.
const QP_ALLOWED_ATTRS = [
    'align','alt','bgcolor','border','cellpadding','cellspacing','class','colspan','dir',
    'height','hspace','rowspan','size','style','title','valign','vspace','width',
];

function qp_cid_map(PhpMimeMailParser\Parser $parser): array {
    $map = [];
    foreach ($parser->getAttachments(true) as $att) {
        $cid = trim((string)$att->getContentID(), '<>');
        if ($cid === '') continue;
        $type = (string)$att->getContentType();
        if (stripos($type, 'image/') !== 0) continue;
        $bytes = $att->getContent();
        if (strlen($bytes) > 2097152) continue; // 2 MiB per inline image
        $map[$cid] = 'data:' . preg_replace('~[^a-z0-9/+.-]~i', '', $type) . ';base64,' . base64_encode($bytes);
    }
    return $map;
}

function qp_sanitize_html(string $html, array $cids, bool $allow_remote_images): array {
    $remote_blocked = 0;
    if (trim($html) === '') return ['', 0];

    $doc = new DOMDocument();
    $previous = libxml_use_internal_errors(true);
    // The meta forces UTF-8 interpretation; the message body was already decoded upstream.
    $doc->loadHTML('<?xml encoding="UTF-8"><meta charset="utf-8">' . $html,
        LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    $xpath = new DOMXPath($doc);

    // Drop dangerous subtrees outright, contents included.
    foreach ($xpath->query('//script|//style|//iframe|//frame|//frameset|//object|//embed|//applet|//form|//input|//button|//select|//textarea|//base|//link|//meta|//noscript|//svg|//math|//template|//portal|//comment()') as $node) {
        if ($node->parentNode) $node->parentNode->removeChild($node);
    }

    // Walk every remaining element: unwrap unknown tags, scrub attributes.
    $elements = iterator_to_array($xpath->query('//*'), false);
    foreach ($elements as $el) {
        if (!$el instanceof DOMElement || !$el->parentNode) continue;
        $tag = strtolower($el->nodeName);

        if ($tag === 'html' || $tag === 'head') continue;

        if (!in_array($tag, QP_ALLOWED_TAGS, true)) {
            // Unwrap rather than delete: keep the text, lose the element.
            while ($el->firstChild) $el->parentNode->insertBefore($el->firstChild, $el);
            $el->parentNode->removeChild($el);
            continue;
        }

        foreach (iterator_to_array($el->attributes, false) as $attr) {
            $name = strtolower($attr->nodeName);
            $value = (string)$attr->nodeValue;

            if ($tag === 'a' && $name === 'href') continue;   // handled below
            if ($tag === 'img' && $name === 'src') continue;  // handled below

            // on*, srcset, formaction, xlink:*, data-* are all dropped by the whitelist.
            if (!in_array($name, QP_ALLOWED_ATTRS, true)) { $el->removeAttribute($attr->nodeName); continue; }
            if ($name === 'style') {
                if (preg_match('~expression\s*\(|javascript:|@import|behavior\s*:~i', $value)) {
                    $el->removeAttribute($attr->nodeName);
                } elseif (!$allow_remote_images && preg_match('~url\s*\(~i', $value)) {
                    // A CSS url() is a remote fetch just like an <img>. The iframe CSP also
                    // blocks it, but the rule belongs here too rather than in one place only.
                    $stripped = preg_replace('~url\s*\([^)]*\)~i', 'none', $value);
                    $el->setAttribute('style', $stripped);
                }
            }
        }

        if ($tag === 'a') {
            $href = trim((string)$el->getAttribute('href'));
            $el->removeAttribute('href');
            $el->setAttribute('class', 'qp-deadlink');
            if ($href !== '' && stripos($href, 'cid:') !== 0) {
                // Show the real destination next to the link text. This is the payload an
                // admin is actually looking for, and it must not be clickable.
                $marker = $doc->createElement('span');
                $marker->setAttribute('class', 'qp-url');
                $marker->appendChild($doc->createTextNode(sm_i18n_text(' [連結→ ') . $href . ' ]'));
                if ($el->parentNode) $el->parentNode->insertBefore($marker, $el->nextSibling);
            }
        }

        if ($tag === 'img') {
            $src = trim((string)$el->getAttribute('src'));
            $el->removeAttribute('src');
            if (stripos($src, 'cid:') === 0) {
                $cid = substr($src, 4);
                if (isset($cids[$cid])) { $el->setAttribute('src', $cids[$cid]); continue; }
                $el->setAttribute('alt', sm_i18n_text('（內嵌圖片遺失）'));
                continue;
            }
            if ($src !== '' && preg_match('~^https?://~i', $src)) {
                if ($allow_remote_images) { $el->setAttribute('src', $src); continue; }
                $remote_blocked++;
                $el->setAttribute('class', trim($el->getAttribute('class') . ' qp-blocked-img'));
                $el->setAttribute('alt', sm_i18n_text('［外部圖片已封鎖］ ') . $src);
                continue;
            }
            if (stripos($src, 'data:image/') === 0 && strlen($src) <= 2097152) {
                $el->setAttribute('src', $src);
            } else {
                $el->setAttribute('alt', sm_i18n_text('（圖片已移除）'));
            }
        }
    }

    $body = $doc->getElementsByTagName('body')->item(0);
    $out = '';
    if ($body) {
        foreach ($body->childNodes as $child) $out .= $doc->saveHTML($child);
    }
    return [$out, $remote_blocked];
}

function qp_escape($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function qp_error(int $status, string $message): void {
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>隔離郵件預覽</title><h1>無法預覽郵件</h1><p>' . qp_escape($message) . '</p></html>';
    exit;
}

$hash = $_GET['hash'] ?? '';
$outbound = isset($_GET['outbound_id']);
if ($outbound) {
    // Numeric IDs are accepted only for the administrator's outbound hold list.
    if (($_SESSION['mailcow_cc_role'] ?? '') !== 'admin') {
        qp_error(403, '只有管理員可以檢視外寄攔截郵件。');
    }
    $id = $_GET['outbound_id'];
    if (!is_string($id) || !preg_match('/^[1-9][0-9]{0,9}$/D', $id)) {
        qp_error(404, '郵件不存在或已處理。');
    }
    $stmt = $pdo->prepare('SELECT * FROM outbound_hold WHERE id = :id AND released = 0');
    $stmt->execute([':id' => $id]);
    $message = $stmt->fetch(PDO::FETCH_ASSOC);
} else {
    // Reuse the per-message bearer token already present in native digest links.
    // An ID alone must never grant access to inbound message content.
    if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/D', $hash)) {
        qp_error(404, '預覽連結無效，請使用隔離郵件報告中的連結。');
    }
    $message = quarantine('hash_details', $hash);
    if ($message) {
        $stmt = $pdo->prepare('SELECT 1 FROM mailbox INNER JOIN user_acl ON mailbox.username = user_acl.username WHERE mailbox.username = :rcpt AND user_acl.quarantine = 1');
        $stmt->execute([':rcpt' => $message['rcpt']]);
        if (!$stmt->fetchColumn()) $message = false;
    }
}
if (!$message) {
    qp_error(404, '郵件已放行、刪除、超過保存期限，或您沒有隔離郵件權限。');
}
if (strlen($message['msg'] ?? '') > 10485760) {
    qp_error(413, '郵件超過 10 MiB，無法安全預覽。請聯絡郵件管理員協助確認。');
}
if (empty($message['msg'])) qp_error(422, '這封郵件沒有可供預覽的內容。');

try {
    $parser = new PhpMimeMailParser\Parser();
    $parser->setText($message['msg']);
    $converter = new Html2Text\Html2Text();
    $attachments = [];
    // Keep attachments in memory under the message-size cap, without writing or serving files.
    foreach ($parser->getAttachments(true) as $attachment) {
        $attachments[] = [$attachment->getFilename(), $attachment->getContentType(), strlen($attachment->getContent())];
    }
    $data = [
        'subject' => $parser->getHeader('subject') ?: ($message['subject'] ?? '（無主旨）'),
        'header_from' => $parser->getHeader('from') ?: '—',
        'env_from' => $message['sender'] ?? '—',
        'recipients' => [['address' => $message['rcpt'] ?? '', 'type' => 'smtp']],
        'action' => $outbound ? 'reject' : ($message['action'] ?? ''),
        'score' => $message['score'] ?? 0,
        'symbols' => json_decode($message['symbols'] ?? '[]', true),
        'attachments' => $attachments,
        'text_plain' => $parser->getMessageBody('text') ?: '',
        'text_html' => $converter->convert($parser->getMessageBody('html')),
    ];
    $raw_html = (string)$parser->getMessageBody('html');
    [$data['html_render'], $data['blocked_images']] =
        qp_sanitize_html($raw_html, qp_cid_map($parser), $qp_show_images);
} catch (Throwable $error) {
    error_log('Quarantine preview: message parsing failed');
    qp_error(422, '無法解析這封郵件，請聯絡郵件管理員協助確認。');
}
if ($outbound && ($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
header('Content-Type: text/html; charset=UTF-8');
$labels = ['reject' => '拒收', 'add header' => '加標記（已投遞至垃圾郵件匣）', 'rewrite subject' => '改寫主旨（已投遞）'];
$symbols = [];
foreach ((is_array($data['symbols']) ? $data['symbols'] : []) as $key => $symbol) {
    if (!is_array($symbol)) continue;
    $symbols[] = ($symbol['name'] ?? (string)$key) . ' (' . number_format((float)($symbol['score'] ?? 0), 2) . ')';
}
?>
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>隔離郵件內容預覽</title>
  <style>
    *{box-sizing:border-box}body{margin:0;background:#f3f6f9;color:#172b4d;font:16px/1.65 system-ui,sans-serif}main{max-width:1000px;margin:24px auto;padding:24px;background:white;border:1px solid #dfe7ef;border-radius:10px}h1{color:#063567;font-size:1.6rem}h2{font-size:1.1rem}dt{font-weight:700}dd{margin:0 0 12px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7fafc;border:1px solid #dfe7ef;border-radius:6px;padding:16px;font:inherit;max-height:65vh;overflow:auto}.notice{background:#edf6fa;padding:12px;border-left:4px solid #12a9bd}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:24px}.button{padding:10px 16px;background:#007f91;color:white;border-radius:6px;text-decoration:none}.delete{background:#a52e27}.muted{color:#5b6b7a;font-size:.9rem}.qp-frame{width:100%;height:60vh;border:1px solid #dfe7ef;border-radius:6px;background:white}.warn{background:#fff6e5;border-left:4px solid #d98c00;padding:12px}.tabnote{margin:16px 0 6px}@media(max-width:650px){main{margin:0;padding:16px;border-radius:0}}
  </style>
</head>
<body><main>
  <h1>隔離郵件內容預覽</h1>
  <p class="notice">先確認寄件者與內文，再決定是否放行。內文以<strong>原始 HTML 版面</strong>顯示於沙箱框架中：腳本、表單、外掛一律移除，<strong>連結全部失效並標示真實網址</strong>，外部圖片預設不載入。</p>
  <?php if (!empty($message['virus']) || strpos($message['symbols'] ?? '', 'VIRUS_FOUND') !== false): ?>
  <p class="notice">⚠ 這封郵件曾命中病毒掃描，請聯絡管理員確認安全。</p>
  <?php endif; ?>
  <dl>
    <dt>主旨</dt><dd id="preview-subject" data-sm-raw><?= qp_escape($data['subject']) ?></dd>
    <dt>信封寄件者</dt><dd data-sm-raw><?= qp_escape($data['env_from']) ?></dd>
    <dt>標頭 From</dt><dd data-sm-raw><?= qp_escape($data['header_from']) ?></dd>
    <dt>收件者</dt><dd data-sm-raw><?= qp_escape($message['rcpt']) ?></dd>
    <dt>處理結果／分數</dt><dd><?= qp_escape($labels[$data['action']] ?? $data['action']) ?>／<?= qp_escape($data['score']) ?></dd>
    <dt>隔離時間</dt><dd><?= qp_escape($message['created'] ?? '—') ?></dd>
    <dt>命中項目</dt><dd><?= qp_escape(implode('、', $symbols) ?: '—') ?></dd>
    <dt>附件（僅列資訊）</dt><dd id="preview-attachments"><?php if (!$attachments): ?>無<?php else: ?><ul data-sm-raw><?php foreach ($attachments as $attachment): ?><li><?= qp_escape($attachment[0] ?: '（無檔名）') ?> — <?= qp_escape($attachment[1]) ?>，<?= (int)$attachment[2] ?> bytes</li><?php endforeach; ?></ul><?php endif; ?></dd>
  </dl>
  <?php if ($data['html_render'] !== ''): ?>
  <h2>郵件內文（原始 HTML 版面）</h2>
  <?php if (!empty($data['blocked_images'])): ?>
  <p class="warn">已封鎖 <?= (int)$data['blocked_images'] ?> 張外部圖片。載入它們會讓寄件者知道這個信箱有效、而且有人正在讀這封信 —— 只有在你確定需要看完整版面時才載入。
    <a href="?<?= qp_escape(http_build_query(array_merge($_GET, ['images' => '1']))) ?>">仍要載入外部圖片</a></p>
  <?php elseif ($qp_show_images): ?>
  <p class="warn">外部圖片已載入，寄件者可能已得知這封信被讀取。
    <a href="?<?= qp_escape(http_build_query(array_diff_key($_GET, ['images' => '']))) ?>">改回封鎖</a></p>
  <?php endif; ?>
  <iframe class="qp-frame" id="preview-html-frame" sandbox referrerpolicy="no-referrer"
          title="郵件 HTML 內容（沙箱）"
          srcdoc="<?= qp_escape('<!doctype html><meta charset="utf-8"><style>html{font:16px/1.6 system-ui,sans-serif;color:#172b4d;padding:8px}img{max-width:100%}.qp-deadlink{color:#a52e27;text-decoration:underline dotted;cursor:not-allowed}.qp-url{color:#a52e27;font:13px/1.5 ui-monospace,monospace;overflow-wrap:anywhere}.qp-blocked-img{display:inline-block;min-width:120px;padding:4px 8px;border:1px dashed #d98c00;background:#fff6e5;color:#8a5a00;font-size:13px}</style>' . $data['html_render']) ?>"></iframe>
  <p class="muted">框架無腳本權限、同源已隔離。紅色虛線為原信連結，後方 <code>[連結→ … ]</code> 是它真正指向的網址。</p>
  <?php endif; ?>
  <h2 class="tabnote">郵件內文（純文字）</h2><pre id="preview-text"<?= $data['text_plain'] ? ' data-sm-raw' : '' ?>><?= qp_escape($data['text_plain'] ?: '（無純文字部分）') ?></pre>
  <?php if ($data['html_render'] === ''): ?>
  <h2>HTML 郵件轉為純文字</h2><pre id="preview-html"<?= $data['text_html'] ? ' data-sm-raw' : '' ?>><?= qp_escape($data['text_html'] ?: '（無 HTML 部分）') ?></pre>
  <?php endif; ?>
  <?php if (!$outbound): ?>
  <div class="actions">
    <a class="button" id="preview-release" href="/qhandler/release/<?= qp_escape($hash) ?>"><?= $data['action'] === 'reject' ? '確認安全，前往放行' : '前往複製至收件匣' ?></a>
    <a class="button delete" id="preview-delete" href="/qhandler/delete/<?= qp_escape($hash) ?>">前往刪除</a>
  </div>
  <p class="muted">下一頁仍需按「確認」才會執行。此連結包含這一封郵件的存取權限，請勿轉寄。</p>
  <?php else: ?>
  <p class="muted">請回到 Spam Manager「外寄攔截」分頁決定是否放行。</p>
  <?php endif; ?>
</main></body></html>

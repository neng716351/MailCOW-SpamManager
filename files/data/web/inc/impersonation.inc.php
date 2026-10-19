<?php
// Structured form for administrator-managed display-name protection rules.
function impersonation_validate($name, $emails) {
  if (!is_string($name) || (!is_string($emails) && !is_array($emails))) throw new InvalidArgumentException('欄位格式不正確。');
  $name = trim($name);
  if ($name === '' || mb_strlen($name) > 80 || preg_match('/[\x00-\x1f\x7f]/u', $name)) {
    throw new InvalidArgumentException('顯示名稱必填、最多 80 字，且不得包含換行。');
  }
  if (!is_array($emails)) $emails = preg_split('/[\s,;]+/u', trim((string)$emails), -1, PREG_SPLIT_NO_EMPTY);
  if (count($emails) < 1 || count($emails) > 20) throw new InvalidArgumentException('請輸入 1 至 20 個允許的寄件信箱。');
  $clean = [];
  foreach ($emails as $email) {
    if (!is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) {
      throw new InvalidArgumentException('允許的寄件信箱格式不正確。');
    }
    $clean[] = strtolower($email);
  }
  return ['name' => $name, 'emails' => array_values(array_unique($clean))];
}
function impersonation_content($model) {
  $model = impersonation_validate($model['name'], $model['emails']);
  $encode = function($s) { return json_encode($s, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR); };
  $name = $encode('/' . preg_quote($model['name'], '/') . '/');
  $allowed = implode('|', array_map(function($email) { return preg_quote($email, '/'); }, $model['emails']));
  $from = $encode('/^(?!(?:' . $allowed . ')$).*$/i');
  $metadata = base64_encode(json_encode($model, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
  return "# mailcow-impersonation-form-v1: " . $metadata . "\n" . <<<RULE
priority = 20;
header = {
  "From" = $name;
};
from_mime = $from;
expression = "header:from & from_mime";
apply "default" {
  MAILCOW_BLACK = 100.0;
  actions {
    "add header" = 8.0;
    greylist = 9997.0;
    quarantine = 9998.0;
    reject = 9999.0;
  }
}
symbols [
  "MAILCOW_BLACK"
]
RULE;
}
function impersonation_model($content) {
  $content = trim(str_replace("\r\n", "\n", $content));
  if (!preg_match('/^# mailcow-impersonation-form-v1: ([A-Za-z0-9+\/=]+)\n/', $content, $m)) return null;
  try {
    $model = json_decode(base64_decode($m[1], true), true, 16, JSON_THROW_ON_ERROR);
    $model = impersonation_validate($model['name'] ?? '', $model['emails'] ?? []);
    return hash_equals(impersonation_content($model), $content) ? $model : null;
  } catch (Throwable $e) { return null; }
}

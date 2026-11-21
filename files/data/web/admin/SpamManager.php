<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/triggers.admin.inc.php';
protect_route(['admin']);
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/header.inc.php';
$_SESSION['return_to'] = $_SERVER['REQUEST_URI'];
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/spammanager.i18n.inc.php';
$js_minifier->add('/web/js/site/spammanager.i18n.js');
$js_minifier->add('/web/js/site/spammanager.translations.js');
$js_minifier->add('/web/js/site/spammanager.js');
$js_minifier->add('/web/js/site/impersonation.js');
$rsettings = array_map(function ($rule) {
  $rule['details'] = rsettings('details', $rule['id']);
  $rule['hash'] = hash('sha256', $rule['details']['content']);
  $rule['impersonation'] = impersonation_model($rule['details']['content']);
  return $rule;
}, rsettings('get'));
$template = 'spammanager.twig';
$template_data = [
  'rsettings' => $rsettings,
  'role' => 'admin',
  'sm_i18n' => sm_i18n_payload(),
  'sm_domain' => sm_install_domain(),
  'acl' => $_SESSION['acl'],
  'acl_json' => json_encode($_SESSION['acl']),
  'lang_admin' => json_encode($lang['admin']),
  'lang_datatables' => json_encode($lang['datatables'])
];
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/footer.inc.php';

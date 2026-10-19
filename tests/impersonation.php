<?php
require_once __DIR__ . '/../files/data/web/inc/impersonation.inc.php';

$model = ['name' => 'Example Display Name', 'emails' => ['User@example.invalid']];
$content = impersonation_content($model);
$roundTrip = impersonation_model($content);

if ($roundTrip !== ['name' => 'Example Display Name', 'emails' => ['user@example.invalid']]) {
  fwrite(STDERR, "Round-trip model check failed.\n");
  exit(1);
}

if (impersonation_model("priority = 20;\n") !== null) {
  fwrite(STDERR, "Unmanaged rule check failed.\n");
  exit(1);
}

try {
  impersonation_validate('', ['user@example.invalid']);
  fwrite(STDERR, "Invalid name was accepted.\n");
  exit(1);
} catch (InvalidArgumentException) {
}

echo "PASS: impersonation rule validation, metadata round-trip, and unmanaged-rule handling.\n";

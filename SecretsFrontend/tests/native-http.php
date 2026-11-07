<?php
declare(strict_types=1);
require_once __DIR__.'/BootstrapFixture.php';
class HookInstance extends SecretsFrontend {public function ProcessHookData(){parent::ProcessHookData();}}
require __DIR__.'/http-symcon.php';

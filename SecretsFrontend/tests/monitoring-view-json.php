<?php
// Exercise the production Symcon evaluator in browser fixtures; no JS reimplementation.
require_once __DIR__.'/../MonitoringView.php';
set_error_handler(static function($severity,$message,$file,$line){throw new ErrorException($message,0,$severity,$file,$line);});
$n=json_decode(stream_get_contents(STDIN),true,96,JSON_THROW_ON_ERROR);
echo json_encode(SecretsFrontendMonitoringView::decorate($n,'/hook/secrets_frontend_123'),JSON_THROW_ON_ERROR);

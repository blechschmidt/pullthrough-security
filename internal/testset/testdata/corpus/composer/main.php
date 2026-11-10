<?php
// Minimal real Composer build for the pull-through proxy test set.
require __DIR__ . '/vendor/autoload.php';

echo class_exists(\Psr\Log\LogLevel::class) ? "psr/log ok\n" : "fail\n";

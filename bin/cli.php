#!/usr/bin/env php
<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;

// phpcs:ignore Squiz.NamingConventions.ValidVariableName.NotCamelCaps
include $_composer_autoload_path ?? __DIR__ . '/../vendor/autoload.php';

$application = new Application('Attestation CLI');
$application->addCommands([
    new \ThePhpFoundation\Attestation\Command\VerifyBundle(),
]);

$application->run();

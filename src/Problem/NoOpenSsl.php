<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use RuntimeException;

class NoOpenSsl extends RuntimeException implements FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Unable to verify without the openssl extension.');
    }
}

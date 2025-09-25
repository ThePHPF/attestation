<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class NoOpenSsl extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Unable to verify without the openssl extension.');
    }
}

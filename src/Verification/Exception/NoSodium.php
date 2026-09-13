<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class NoSodium extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Unable to verify an Ed25519 transparency log signature without the sodium extension.');
    }
}

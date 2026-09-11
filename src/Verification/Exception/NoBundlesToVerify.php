<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class NoBundlesToVerify extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('No bundles were provided to verify; an empty list cannot be considered verified.');
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class UnsupportedBundleContent extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Bundle content is neither a DSSE envelope nor a message signature.');
    }
}

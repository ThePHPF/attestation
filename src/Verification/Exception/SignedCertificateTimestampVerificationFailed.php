<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class SignedCertificateTimestampVerificationFailed extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self(
            'Certificate has a Signed Certificate Timestamp referencing a trusted Certificate Transparency ' .
            'log key, but its signature does not verify',
        );
    }
}

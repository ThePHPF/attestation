<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class UntrustedCertificateTransparencyLogKey extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self(
            'Certificate has no Signed Certificate Timestamp referencing a Certificate Transparency ' .
            'log key trusted by the trusted root',
        );
    }
}

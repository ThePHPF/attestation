<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use RuntimeException;

use function implode;
use function is_array;
use function sprintf;

class IssuerCertificateVerificationFailed extends RuntimeException implements FailedToVerifyArtifact
{
    /** @param array<array-key,string>|string $issuer */
    public static function fromIssuer($issuer): self
    {
        return new self(sprintf(
            'Failed to verify the attestation certificate was issued by trusted root %s',
            is_array($issuer) ? implode(',', $issuer) : $issuer,
        ));
    }
}

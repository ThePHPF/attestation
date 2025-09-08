<?php

declare(strict_types=1);

namespace ThePHPFoundation\Attestation\Problem;

use RuntimeException;

use function implode;
use function is_array;
use function sprintf;

class NoIssuerCertificateInTrustedRoot extends RuntimeException implements FailedToVerifyArtifact
{
    /** @param array<array-key,string>|string $issuer */
    public static function fromIssuer($issuer): self
    {
        return new self(sprintf(
            'Could not find a trusted root certificate for issuer %s',
            is_array($issuer) ? implode(',', $issuer) : $issuer,
        ));
    }
}

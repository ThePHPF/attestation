<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class CertificateIdentityMismatch extends FailedToVerifyArtifact
{
    public static function from(string $expected, string $actual): self
    {
        return new self(sprintf(
            'Attestation certificate identity mismatch; expected "%s", was one of "%s"',
            $expected,
            $actual,
        ));
    }
}

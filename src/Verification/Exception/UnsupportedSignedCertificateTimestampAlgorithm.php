<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class UnsupportedSignedCertificateTimestampAlgorithm extends FailedToVerifyArtifact
{
    public static function fromAlgorithms(int $hashAlgorithm, int $signatureAlgorithm): self
    {
        return new self(sprintf(
            'Unsupported Signed Certificate Timestamp algorithm combination: hash=%d, signature=%d; ' .
            'only SHA-256/ECDSA is currently supported',
            $hashAlgorithm,
            $signatureAlgorithm,
        ));
    }
}

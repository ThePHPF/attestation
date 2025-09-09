<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use RuntimeException;

use function sprintf;
use function substr;

class DigestMismatch extends RuntimeException implements FailedToVerifyArtifact
{
    public static function fromChecksumMismatch(string $expected, string $actual): self
    {
        return new self(sprintf(
            'Failed checksum verification. Expected %s..., was %s...',
            substr($expected, 0, 8),
            substr($actual, 0, 8),
        ));
    }
}

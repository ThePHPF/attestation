<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use RuntimeException;

use function sprintf;

class MismatchingExtensionValues extends RuntimeException implements FailedToVerifyArtifact
{
    public static function from(string $extension, string $expected, string $actual): self
    {
        return new self(sprintf(
            'Attestation certificate extension %s mismatch; expected "%s", was "%s"',
            $extension,
            $expected,
            $actual,
        ));
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class ReleaseTagMismatch extends FailedToVerifyArtifact
{
    public static function from(string $expected, string $actual): self
    {
        return new self(sprintf(
            'Attestation release tag mismatch; expected "%s", was "%s"',
            $expected,
            $actual,
        ));
    }
}

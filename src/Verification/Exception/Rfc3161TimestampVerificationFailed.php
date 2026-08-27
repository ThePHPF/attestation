<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class Rfc3161TimestampVerificationFailed extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Attestation %d has an RFC 3161 timestamp with an invalid CMS signature',
            $bundleIndex,
        ));
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class InvalidRfc3161TimestampFormat extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Attestation %d has an RFC 3161 timestamp with an unparseable generalized time',
            $bundleIndex,
        ));
    }
}

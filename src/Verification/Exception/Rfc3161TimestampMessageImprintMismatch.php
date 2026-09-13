<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class Rfc3161TimestampMessageImprintMismatch extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Attestation %d has an RFC 3161 timestamp whose messageImprint does not match the bundle\'s signed content',
            $bundleIndex,
        ));
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class TimestampAuthorityOutsideValidityPeriod extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, int $genTime, int $tsaValidFrom, ?int $tsaValidTo): self
    {
        return new self(sprintf(
            'Attestation %d has an RFC 3161 timestamp (%d) outside the resolved timestamp authority\'s ' .
            'validity window (%d - %s)',
            $bundleIndex,
            $genTime,
            $tsaValidFrom,
            $tsaValidTo === null ? 'unbounded' : (string) $tsaValidTo,
        ));
    }
}

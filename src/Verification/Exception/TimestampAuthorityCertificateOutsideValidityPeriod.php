<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class TimestampAuthorityCertificateOutsideValidityPeriod extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, int $genTime, int $certificateValidFrom, int $certificateValidTo): self
    {
        return new self(sprintf(
            'Attestation %d has an RFC 3161 timestamp (%d) outside the timestamp authority\'s ' .
            'certificate validity window (%d - %d)',
            $bundleIndex,
            $genTime,
            $certificateValidFrom,
            $certificateValidTo,
        ));
    }
}

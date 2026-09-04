<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class TransparencyLogKeyOutsideValidityPeriod extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, int $integratedTime, int $keyValidFrom, int|null $keyValidTo): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has an integrated time (%d) outside the ' .
            'resolved transparency log key\'s validity window (%d - %s)',
            $bundleIndex,
            $integratedTime,
            $keyValidFrom,
            $keyValidTo === null ? 'unbounded' : (string) $keyValidTo,
        ));
    }
}

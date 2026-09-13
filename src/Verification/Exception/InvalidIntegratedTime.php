<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class InvalidIntegratedTime extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, int $integratedTime, int $certificateValidFrom, int $certificateValidTo): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has an integrated time (%d) outside the ' .
            'signing certificate\'s validity window (%d - %d)',
            $bundleIndex,
            $integratedTime,
            $certificateValidFrom,
            $certificateValidTo,
        ));
    }
}

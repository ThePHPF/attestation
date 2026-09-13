<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class MissingTimestampEvidence extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Attestation %d has no timestamp evidence: no transparency log entry has an integrated time, ' .
            'and no RFC 3161 timestamp is present',
            $bundleIndex,
        ));
    }
}

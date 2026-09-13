<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class InvalidLogIndex extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, int $logIndex): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has an invalid log index: %d',
            $bundleIndex,
            $logIndex,
        ));
    }
}

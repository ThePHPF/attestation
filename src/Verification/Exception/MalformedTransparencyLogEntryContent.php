<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class MalformedTransparencyLogEntryContent extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex, string $reason): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has malformed content: %s',
            $bundleIndex,
            $reason,
        ));
    }
}

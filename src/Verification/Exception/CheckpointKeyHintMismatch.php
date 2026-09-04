<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class CheckpointKeyHintMismatch extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has a checkpoint signature key hint that does '
            . 'not match the resolved transparency log key',
            $bundleIndex,
        ));
    }
}

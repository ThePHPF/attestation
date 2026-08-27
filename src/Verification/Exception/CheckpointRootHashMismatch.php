<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class CheckpointRootHashMismatch extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has a checkpoint that is validly signed but whose '
            . 'root hash does not match the entry\'s inclusion proof',
            $bundleIndex,
        ));
    }
}

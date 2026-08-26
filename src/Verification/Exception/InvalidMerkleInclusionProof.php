<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class InvalidMerkleInclusionProof extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has an invalid Merkle inclusion proof',
            $bundleIndex,
        ));
    }
}

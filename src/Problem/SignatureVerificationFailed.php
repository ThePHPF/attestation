<?php

declare(strict_types=1);

namespace ThePHPFoundation\Attestation\Problem;

use RuntimeException;

use function sprintf;

class SignatureVerificationFailed extends RuntimeException implements FailedToVerifyArtifact
{
    public static function forIndex(int $attestationIndex): self
    {
        return new self(sprintf(
            'Failed to verify DSSE Envelope payload signature for attestation %d',
            $attestationIndex,
        ));
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use function sprintf;

class SignatureVerificationFailed extends FailedToVerifyArtifact
{
    public static function forIndex(int $attestationIndex): self
    {
        return new self(sprintf(
            'Failed to verify DSSE Envelope payload signature for attestation %d',
            $attestationIndex,
        ));
    }
}

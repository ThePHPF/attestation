<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class ReleaseTagDigestMismatch extends FailedToVerifyArtifact
{
    public static function from(string $digestAlgorithm, string $expectedTagDigest): self
    {
        return new self(sprintf(
            'Attestation has no subject with digest %s:%s',
            $digestAlgorithm,
            $expectedTagDigest,
        ));
    }
}

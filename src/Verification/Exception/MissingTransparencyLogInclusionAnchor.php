<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class MissingTransparencyLogInclusionAnchor extends FailedToVerifyArtifact
{
    public static function forIndex(int $bundleIndex): self
    {
        return new self(sprintf(
            'Transparency log entry for attestation %d has neither a signed entry timestamp nor a ' .
            'checkpoint, so its inclusion in the log cannot be authenticated',
            $bundleIndex,
        ));
    }
}

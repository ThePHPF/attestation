<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class NoTransparencyLogKeyInTrustedRoot extends FailedToVerifyArtifact
{
    public static function fromLogId(string $logIdHex): self
    {
        return new self(sprintf(
            'Could not find a trusted transparency log key for logID %s',
            $logIdHex,
        ));
    }
}

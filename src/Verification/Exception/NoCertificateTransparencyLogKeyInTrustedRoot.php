<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class NoCertificateTransparencyLogKeyInTrustedRoot extends FailedToVerifyArtifact
{
    public static function fromLogId(string $logIdHex): self
    {
        return new self(sprintf(
            'Could not find a trusted Certificate Transparency log key for logID %s',
            $logIdHex,
        ));
    }
}

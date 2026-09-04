<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class UnsupportedTransparencyLogEntryKind extends FailedToVerifyArtifact
{
    public static function fromKind(string $kind): self
    {
        return new self(sprintf(
            'Unsupported transparency log entry kind "%s"; only hashedrekord, dsse and intoto are currently supported',
            $kind,
        ));
    }
}

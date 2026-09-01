<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class NoBcmath extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self(
            'Cannot verify a message-signature bundle from a digest alone without the bcmath extension.',
        );
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class CannotVerifyMessageSignatureWithoutArtifact extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self(
            'Cannot verify a message-signature bundle without the real artifact file; ' .
            'digest-only verification is only supported for ECDSA P-256 signing keys.',
        );
    }
}

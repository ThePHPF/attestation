<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class CannotVerifyMessageSignatureWithoutArtifact extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self(
            'Cannot verify a message-signature bundle without the real artifact file; ' .
            'digest-only verification is not supported for this bundle type, since the signature ' .
            'covers the artifact bytes directly and cannot be safely checked from a digest alone.',
        );
    }
}

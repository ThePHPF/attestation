<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

class InvalidSubjectDefinition extends FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Unable to extract subject digest from the dsseEnvelope in the attestation.');
    }
}

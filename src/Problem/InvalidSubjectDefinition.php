<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Problem;

use RuntimeException;

class InvalidSubjectDefinition extends RuntimeException implements FailedToVerifyArtifact
{
    public static function new(): self
    {
        return new self('Unable to extract subject digest from the dsseEnvelope in the attestation.');
    }
}

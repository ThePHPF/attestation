<?php

declare(strict_types=1);

namespace ThePHPFoundation\Attestation\Problem;

use RuntimeException;

use function sprintf;
use function strlen;

class InvalidDerEncodedStringLength extends RuntimeException implements FailedToVerifyArtifact
{
    public static function fromDerString(string $derEncodedString, int $expectedLength): self
    {
        return new self(sprintf(
            'DER encoded string length of "%s" was wrong; expected %d characters, was actually %d characters',
            $derEncodedString,
            $expectedLength,
            strlen($derEncodedString),
        ));
    }
}

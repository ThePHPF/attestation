<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function array_map;
use function implode;
use function sprintf;
use function substr;

class DigestMismatch extends FailedToVerifyArtifact
{
    public static function fromChecksumMismatch(string $expected, string $actual): self
    {
        return new self(sprintf(
            'Failed checksum verification. Expected %s..., was %s...',
            substr($expected, 0, 8),
            substr($actual, 0, 8),
        ));
    }

    /** @param non-empty-list<string> $subjectDigests */
    public static function fromNoMatchingSubject(string $expected, array $subjectDigests): self
    {
        return new self(sprintf(
            'Failed checksum verification. Expected %s..., was none of %s',
            substr($expected, 0, 8),
            implode(', ', array_map(static fn (string $digest): string => substr($digest, 0, 8) . '...', $subjectDigests)),
        ));
    }
}

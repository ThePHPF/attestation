<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class UnsupportedBundleMediaType extends FailedToVerifyArtifact
{
    public static function fromMediaType(string $mediaType): self
    {
        return new self(sprintf('Unsupported bundle mediaType: %s', $mediaType));
    }
}

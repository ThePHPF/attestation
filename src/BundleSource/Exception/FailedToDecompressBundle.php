<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use function sprintf;

class FailedToDecompressBundle extends BundleSourceException
{
    public static function fromUrl(string $bundleUrl): self
    {
        return new self(sprintf(
            'Failed to Snappy-decompress attestation bundle from "%s"',
            $bundleUrl,
        ));
    }
}

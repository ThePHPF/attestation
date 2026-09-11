<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use function sprintf;

class BundleResponseTooLarge extends BundleSourceException
{
    public static function fromUrl(string $bundleUrl, int $size, int $maxSize): self
    {
        return new self(sprintf(
            'Refusing to decompress attestation bundle from "%s": response was %d bytes, exceeding the %d byte limit',
            $bundleUrl,
            $size,
            $maxSize,
        ));
    }
}

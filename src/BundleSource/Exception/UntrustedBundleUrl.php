<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use function sprintf;

class UntrustedBundleUrl extends BundleSourceException
{
    public static function fromUrl(string $bundleUrl): self
    {
        return new self(sprintf(
            'Refusing to fetch attestation bundle from "%s": only https:// URLs are allowed',
            $bundleUrl,
        ));
    }
}

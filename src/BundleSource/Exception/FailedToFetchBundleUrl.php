<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use function sprintf;

class FailedToFetchBundleUrl extends BundleSourceException
{
    public static function fromUrl(string $bundleUrl, int|null $statusCode = null): self
    {
        return new self(sprintf(
            'Failed to fetch attestation bundle from "%s" (HTTP status: %s)',
            $bundleUrl,
            $statusCode !== null ? (string) $statusCode : 'unknown',
        ));
    }
}

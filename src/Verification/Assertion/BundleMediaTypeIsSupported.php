<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleMediaType;

use function in_array;

final class BundleMediaTypeIsSupported implements VerifyBundleCheck
{
    private const SUPPORTED_BUNDLE_MEDIA_TYPES = [
        'application/vnd.dev.sigstore.bundle+json;version=0.1',
        'application/vnd.dev.sigstore.bundle+json;version=0.2',
        'application/vnd.dev.sigstore.bundle+json;version=0.3',
        'application/vnd.dev.sigstore.bundle.v0.3+json',
    ];

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        if (! in_array($bundle->mediaType(), self::SUPPORTED_BUNDLE_MEDIA_TYPES, true)) {
            throw UnsupportedBundleMediaType::fromMediaType($bundle->mediaType());
        }
    }
}

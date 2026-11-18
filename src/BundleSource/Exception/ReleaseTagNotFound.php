<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use function sprintf;

class ReleaseTagNotFound extends BundleSourceException
{
    public static function from(string $owner, string $repo, string $tagName): self
    {
        return new self(sprintf('Tag %s was not found in %s/%s', $tagName, $owner, $repo));
    }
}

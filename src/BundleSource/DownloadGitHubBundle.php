<?php

// phpcs:ignoreFile

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use function class_alias;

class_alias(DownloadGitHubProvenance::class, DownloadGitHubBundle::class);

if (false) { // @phpstan-ignore if.alwaysFalse
    /** @deprecated use {@see DownloadGitHubProvenance} instead */
    class DownloadGitHubBundle extends DownloadGitHubProvenance
    {
    }
}

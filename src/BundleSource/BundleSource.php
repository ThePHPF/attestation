<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;

interface BundleSource
{
    /** @return non-empty-list<Bundle> */
    public function getBundles(FilenameWithChecksum $file): array;
}

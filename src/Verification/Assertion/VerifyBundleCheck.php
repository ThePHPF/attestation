<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\FailedToVerifyArtifact;

interface VerifyBundleCheck
{
    /** @throws FailedToVerifyArtifact */
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void;
}

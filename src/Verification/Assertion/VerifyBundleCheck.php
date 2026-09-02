<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\FailedToVerifyArtifact;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
interface VerifyBundleCheck
{
    /** @throws FailedToVerifyArtifact */
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void;
}

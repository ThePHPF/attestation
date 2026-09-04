<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\FailedToVerifyArtifact;

interface VerifyBundle
{
    /**
     * @param non-empty-list<Bundle> $bundles
     *
     * @throws FailedToVerifyArtifact
     */
    public function verify(array $bundles, FilenameWithChecksum $file): void;
}

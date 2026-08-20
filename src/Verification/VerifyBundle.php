<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\FailedToVerifyArtifact;

interface VerifyBundle
{
    /**
     * @param non-empty-list<Bundle>          $bundles
     * @param non-empty-string                $expectedSubjectName
     * @param array<non-empty-string, string> $extensionsToVerify
     *
     * @throws FailedToVerifyArtifact
     */
    public function verify(
        array $bundles,
        FilenameWithChecksum $file,
        string $expectedSubjectName,
        array $extensionsToVerify
    ): void;
}

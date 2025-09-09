<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use ThePhpFoundation\Attestation\Problem\FailedToVerifyArtifact;

interface VerifyAttestation
{
    /**
     * @param non-empty-string            $owner
     * @param non-empty-string            $expectedSubjectName
     * @param array<Extension::*, string> $extensionsToVerify
     *
     * @throws FailedToVerifyArtifact
     */
    public function verify(
        FilenameWithChecksum $file,
        string $owner,
        string $expectedSubjectName,
        array $extensionsToVerify
    ): void;
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use ThePhpFoundation\Attestation\FilenameWithChecksum;

use function sprintf;

class MissingAttestation extends FailedToVerifyArtifact
{
    public static function from(FilenameWithChecksum $filenameWithChecksum): self
    {
        return new self(sprintf(
            'Attestation for %s (sha256:%s) was not found',
            $filenameWithChecksum->filename(),
            $filenameWithChecksum->checksum(),
        ));
    }
}

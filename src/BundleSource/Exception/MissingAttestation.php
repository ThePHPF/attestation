<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use ThePhpFoundation\Attestation\FilenameWithChecksum;

use function sprintf;

class MissingAttestation extends BundleSourceException
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

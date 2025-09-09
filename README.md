# Attestation

A PHP library to aid in verifying artifact attestations. This tool will carry
out some basic verifications that the given file is genuine. The checks it
carries out are:

 * Verifies the attestation certificate was signed by a trusted root
 * Verifies the given OID extensions match what you expect
 * Checks the digest in the attestation record matches the actual file given
 * Verifies the DSSE envelope signature

## Example usage

```php
<?php

use ThePhpFoundation\Attestation\Extension;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\VerifyAttestationWithOpenSsl;
use ThePhpFoundation\Attestation\Problem\FailedToVerifyArtifact;

try {
    VerifyAttestationWithOpenSsl::factory()
        ->verify(
            FilenameWithChecksum::fromFilename($fileYouWantToVerify),
            'your-org', // the org/user in your GH URL, e.g. https://github.com/your-org
            'the-filename', // the filename of the subject when it was built
            [
                Extension::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                Extension::SOURCE_REPOSITORY_URI => 'https://github.com/your-org/your-repo',
                Extension::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/your-org',
            ],
        );
} catch (FailedToVerifyArtifact $issue) {
    // Handle verification failure in the way you see fit...
}
```

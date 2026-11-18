# Attestation

A PHP library to aid in verifying artifact attestations. This tool will carry
out some basic verifications that the given file is genuine. At this time,
the library does not support signing artifacts.

## Library usage

Fetching a bundle from GitHub's Artifact Attestations API and verifying it:

```php
<?php

use ThePhpFoundation\Attestation\AttestationException;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubProvenance;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;

try {
    $file = FilenameWithChecksum::fromFilename($fileYouWantToVerify);

    $bundles = DownloadGitHubProvenance::factory('your-org') // the org/user in your GH URL, e.g. https://github.com/your-org
        ->getBundles($file);

    VerifyBundleWithOpenSsl::factory(
        [
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/your-org/your-repo',
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/your-org',
        ],
        // the workflow that's expected to have produced the signing certificate
        'https://github.com/your-org/your-repo/.github/workflows/build.yml@refs/heads/main',
        // the expected issuer of the signing certificate
        'https://token.actions.githubusercontent.com',
        // the expected predicate type, or null to accept any
        'https://slsa.dev/provenance/v1',
    )
        ->verify($bundles, $file);
} catch (AttestationException $issue) {
    // Handle a failure to fetch or verify the attestation in the way you see fit...
}
```

### GitHub release attestations

Verifying that a file is an asset of a specific GitHub release, using
GitHub's release attestation:

```php
<?php

use ThePhpFoundation\Attestation\AttestationException;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubRelease;
use ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;

try {
    $file = FilenameWithChecksum::fromFilename($fileYouWantToVerify);

    $tag = ResolveGitHubReleaseTag::factory()->resolve('your-org', 'your-repo', '1.2.3');

    $bundles = DownloadGitHubRelease::factory('your-org', 'your-repo', $tag)
        ->getBundles($file);

    VerifyBundleWithOpenSsl::forGitHubRelease($tag)
        ->verify($bundles, $file);
} catch (AttestationException $issue) {
    // Handle a failure to fetch or verify the attestation in the way you see fit...
}
```

## CLI usage

A `verify-bundle` command is provided, implementing a subset of the
[Sigstore conformance CLI protocol](https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md#verify-bundle),
to verify a local Sigstore bundle file against a local artifact:

```bash
php bin/cli.php verify-bundle \
  --bundle=path/to/bundle.json \
  --certificate-identity=https://github.com/your-org/your-repo/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  path/to/artifact
```

Pass `--trusted-root=path/to/trusted-root.jsonl` to verify against a custom
trusted root instead of the one bundled with this library.

To verify a GitHub release attestation instead, pass the release tag and the
git object SHA it points to; `--certificate-identity` and
`--certificate-oidc-issuer` are then not needed:

```bash
php bin/cli.php verify-bundle \
  --bundle=path/to/release-bundle.json \
  --github-release-tag=1.2.3 \
  --github-release-tag-sha=<sha from GET /repos/your-org/your-repo/git/ref/tags/1.2.3> \
  path/to/artifact
```

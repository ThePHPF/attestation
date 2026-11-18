<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\GitHubReleaseTag;
use ThePhpFoundation\Attestation\Verification\Assertion\ArtifactMatchesBundleContent;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneRfc3161Timestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneTimestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateExtensionClaims;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateIdentity;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateOidcIssuer;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateSignedByTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Assertion\PredicateType;
use ThePhpFoundation\Attestation\Verification\Assertion\ReleaseTag;
use ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid;
use ThePhpFoundation\Attestation\Verification\Assertion\SubjectDigestMatchesReleaseTag;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveAnInclusionAnchor;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidCheckpoints;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidInclusionProof;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidSignedEntryTimestamps;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesMatchBundleContent;
use ThePhpFoundation\Attestation\Verification\Assertion\VerifyBundleCheck;
use ThePhpFoundation\Attestation\Verification\Exception\NoBundlesToVerify;

class VerifyBundleWithOpenSsl implements VerifyBundle
{
    private const TRUSTED_ROOT_FILE_PATH               = __DIR__ . '/../../resources/trusted-root.jsonl';
    private const GITHUB_RELEASES_CERTIFICATE_IDENTITY = 'https://dotcom.releases.github.com';

    /** @param list<VerifyBundleCheck> $checks */
    private function __construct(private array $checks)
    {
    }

    /**
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     * @param non-empty-string|null           $expectedPredicateType
     */
    public static function factory(array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer, string|null $expectedPredicateType): self
    {
        return self::withTrustedRootFile(self::TRUSTED_ROOT_FILE_PATH, $extensions, $expectedCertificateIdentity, $expectedOidcIssuer, $expectedPredicateType);
    }

    /**
     * @param non-empty-string                $trustedRootFilePath
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     * @param non-empty-string|null           $expectedPredicateType
     */
    public static function withTrustedRootFile(string $trustedRootFilePath, array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer, string|null $expectedPredicateType): self
    {
        return new self(self::defaultChecks(new TrustedRoot($trustedRootFilePath), $extensions, $expectedCertificateIdentity, $expectedOidcIssuer, $expectedPredicateType));
    }

    public static function forGitHubRelease(GitHubReleaseTag $tag): self
    {
        $trustedRoot = new TrustedRoot(self::TRUSTED_ROOT_FILE_PATH);

        return new self([
            new BundleMediaTypeIsSupported(),
            new BundleHasAtLeastOneRfc3161Timestamp(),
            new Rfc3161TimestampsAreValid($trustedRoot),
            new CertificateSignedByTrustedRoot($trustedRoot),
            new CertificateIdentity(self::GITHUB_RELEASES_CERTIFICATE_IDENTITY),
            new ReleaseTag($tag->tagName()),
            new SubjectDigestMatchesReleaseTag($tag->sha()),
            new ArtifactMatchesBundleContent(),
        ]);
    }

    /**
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     * @param non-empty-string|null           $expectedPredicateType
     *
     * @return list<VerifyBundleCheck>
     */
    private static function defaultChecks(TrustedRoot $trustedRoot, array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer, string|null $expectedPredicateType): array
    {
        $checks = [
            new BundleMediaTypeIsSupported(),
            new BundleHasAtLeastOneTimestamp(),
            new TransparencyLogEntriesHaveValidLogIndex(),
            new TransparencyLogEntriesAreWithinCertificateValidity(),
            new TransparencyLogEntriesAreWithinTransparencyLogKeyValidity($trustedRoot),
            new Rfc3161TimestampsAreValid($trustedRoot),
            new TransparencyLogEntriesHaveValidInclusionProof(),
            new TransparencyLogEntriesHaveValidCheckpoints($trustedRoot),
            new TransparencyLogEntriesHaveValidSignedEntryTimestamps($trustedRoot),
            new TransparencyLogEntriesHaveAnInclusionAnchor(),
            new TransparencyLogEntriesMatchBundleContent(),
            new CertificateSignedByTrustedRoot($trustedRoot),
            new CertificateHasATrustedSignedCertificateTimestamp($trustedRoot),
            new CertificateExtensionClaims($extensions),
            new CertificateOidcIssuer($expectedOidcIssuer),
            new CertificateIdentity($expectedCertificateIdentity),
            new ArtifactMatchesBundleContent(),
        ];

        if ($expectedPredicateType !== null) {
            $checks[] = new PredicateType($expectedPredicateType);
        }

        return $checks;
    }

    /** @inheritDoc */
    public function verify(array $bundles, FilenameWithChecksum $file): void
    {
        if ($bundles === []) {
            throw NoBundlesToVerify::new();
        }

        foreach ($bundles as $bundleIndex => $bundle) {
            foreach ($this->checks as $check) {
                $check->assert($file, $bundleIndex, $bundle);
            }
        }
    }
}

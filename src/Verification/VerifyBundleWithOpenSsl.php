<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\ArtifactMatchesBundleContent;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneTimestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateExtensionClaims;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateIdentity;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateOidcIssuer;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateSignedByTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidCheckpoints;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidInclusionProof;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidSignedEntryTimestamps;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesMatchBundleContent;
use ThePhpFoundation\Attestation\Verification\Assertion\VerifyBundleCheck;

class VerifyBundleWithOpenSsl implements VerifyBundle
{
    public const TRUSTED_ROOT_FILE_PATH = __DIR__ . '/../../resources/trusted-root.jsonl';

    /** @param list<VerifyBundleCheck> $checks */
    public function __construct(private array $checks)
    {
    }

    /**
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     */
    public static function factory(array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer): self
    {
        return self::withTrustedRootFile(self::TRUSTED_ROOT_FILE_PATH, $extensions, $expectedCertificateIdentity, $expectedOidcIssuer);
    }

    /**
     * @param non-empty-string                $trustedRootFilePath
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     */
    public static function withTrustedRootFile(string $trustedRootFilePath, array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer): self
    {
        return new self(self::defaultChecks(new TrustedRoot($trustedRootFilePath), $extensions, $expectedCertificateIdentity, $expectedOidcIssuer));
    }

    /**
     * @param array<non-empty-string, string> $extensions
     * @param non-empty-string                $expectedCertificateIdentity
     * @param non-empty-string                $expectedOidcIssuer
     *
     * @return list<VerifyBundleCheck>
     */
    private static function defaultChecks(TrustedRoot $trustedRoot, array $extensions, string $expectedCertificateIdentity, string $expectedOidcIssuer): array
    {
        return [
            new BundleMediaTypeIsSupported(),
            new BundleHasAtLeastOneTimestamp(),
            new TransparencyLogEntriesHaveValidLogIndex(),
            new TransparencyLogEntriesAreWithinCertificateValidity(),
            new TransparencyLogEntriesAreWithinTransparencyLogKeyValidity($trustedRoot),
            new Rfc3161TimestampsAreValid($trustedRoot),
            new TransparencyLogEntriesHaveValidInclusionProof(),
            new TransparencyLogEntriesHaveValidCheckpoints($trustedRoot),
            new TransparencyLogEntriesHaveValidSignedEntryTimestamps($trustedRoot),
            new TransparencyLogEntriesMatchBundleContent(),
            new CertificateSignedByTrustedRoot($trustedRoot),
            new CertificateHasATrustedSignedCertificateTimestamp($trustedRoot),
            new CertificateExtensionClaims($extensions),
            new CertificateOidcIssuer($expectedOidcIssuer),
            new CertificateIdentity($expectedCertificateIdentity),
            new ArtifactMatchesBundleContent(),
        ];
    }

    /** @inheritDoc */
    public function verify(array $bundles, FilenameWithChecksum $file): void
    {
        foreach ($bundles as $bundleIndex => $bundle) {
            foreach ($this->checks as $check) {
                $check->assert($file, $bundleIndex, $bundle);
            }
        }
    }
}

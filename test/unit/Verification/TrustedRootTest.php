<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\Verification\Exception\NoTransparencyLogKeyInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedTransparencyLogKeyAlgorithm;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function base64_decode;
use function random_bytes;

/** @covers \ThePhpFoundation\Attestation\Verification\TrustedRoot */
final class TrustedRootTest extends TestCase
{
    private const TLOG_VALIDITY_TRUSTED_ROOT = __DIR__ . '/../../fixture/trust-root-tlog-validity-end-inclusive-trusted-root.json';
    private const TLOG_KEY_ID                = 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=';

    private const UNSUPPORTED_ALGORITHM_TRUSTED_ROOT = __DIR__ . '/../../fixture/trusted-root-with-unsupported-key-algorithm.json';
    private const UNSUPPORTED_ALGORITHM_KEY_ID       = 'bm90IGEgcmVhbCBsb2cgaWQ=';

    private const CT_KEY_TRUSTED_ROOT = __DIR__ . '/../../fixture/invalid-ct-key-fail-trusted-root.json';
    private const CT_LOG_ID           = 'G3wUKk6ZK6ffHh/FdCRUE2wVekyzHEEIpSG4savnv0w=';

    private const TSA_TRUSTED_ROOT = __DIR__ . '/../../fixture/rekor2-timestamp-untrusted-tsa-with-embedded-cert-fail-trusted-root.json';

    /** @return non-empty-string */
    private static function decodedLogId(string $base64EncodedLogId): string
    {
        $decoded = base64_decode($base64EncodedLogId);
        Assert::stringNotEmpty($decoded);

        return $decoded;
    }

    public function testResolveTransparencyLogPublicKeyReturnsTheMatchingKey(): void
    {
        $key = (new TrustedRoot(self::TLOG_VALIDITY_TRUSTED_ROOT))->resolveTransparencyLogPublicKey(
            self::decodedLogId(self::TLOG_KEY_ID),
        );

        self::assertSame(TrustedRoot::KEY_DETAILS_ECDSA_P256_SHA_256, $key['keyDetails']);
        self::assertSame(1610452407, $key['validFor']['start']);
        self::assertSame(1689177396, $key['validFor']['end']);
    }

    public function testResolveTransparencyLogPublicKeyThrowsWhenNoKeyMatches(): void
    {
        $this->expectException(NoTransparencyLogKeyInTrustedRoot::class);
        (new TrustedRoot(self::TLOG_VALIDITY_TRUSTED_ROOT))->resolveTransparencyLogPublicKey(random_bytes(32));
    }

    public function testResolveTransparencyLogPublicKeyThrowsForAnUnsupportedAlgorithm(): void
    {
        $this->expectException(UnsupportedTransparencyLogKeyAlgorithm::class);
        (new TrustedRoot(self::UNSUPPORTED_ALGORITHM_TRUSTED_ROOT))->resolveTransparencyLogPublicKey(
            self::decodedLogId(self::UNSUPPORTED_ALGORITHM_KEY_ID),
        );
    }

    public function testTimestampAuthorityCandidatesReturnsAtLeastOneCandidate(): void
    {
        $candidates = (new TrustedRoot(self::TSA_TRUSTED_ROOT))->timestampAuthorityCandidates();

        self::assertNotSame([], $candidates);
        self::assertArrayHasKey('certChainPem', $candidates[0]);
        self::assertArrayHasKey('certChainDer', $candidates[0]);
        self::assertArrayHasKey('validFor', $candidates[0]);
    }

    public function testIsCertificateTransparencyLogIdTrustedReturnsTrueForAKnownLogId(): void
    {
        $trustedRoot = new TrustedRoot(self::CT_KEY_TRUSTED_ROOT);

        self::assertTrue($trustedRoot->isCertificateTransparencyLogIdTrusted(base64_decode(self::CT_LOG_ID)));
    }

    public function testIsCertificateTransparencyLogIdTrustedReturnsFalseForAnUnknownLogId(): void
    {
        $trustedRoot = new TrustedRoot(self::CT_KEY_TRUSTED_ROOT);

        self::assertFalse($trustedRoot->isCertificateTransparencyLogIdTrusted(random_bytes(32)));
    }

    public function testResolveCertificateAuthorityCertificateReturnsTheMatchingCertificate(): void
    {
        $certificate = (new TrustedRoot(self::TLOG_VALIDITY_TRUSTED_ROOT))->resolveCertificateAuthorityCertificate([
            'O' => 'sigstore.dev',
            'CN' => 'sigstore',
        ]);

        self::assertInstanceOf(PemCertificate::class, $certificate);
    }

    public function testResolveCertificateAuthorityCertificateReturnsNullWhenNoSubjectMatches(): void
    {
        $certificate = (new TrustedRoot(self::TLOG_VALIDITY_TRUSTED_ROOT))->resolveCertificateAuthorityCertificate(
            'this subject does not exist',
        );

        self::assertNull($certificate);
    }
}

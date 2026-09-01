<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesMatchBundleContent;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogEntryContentMismatch;

use function base64_encode;
use function bin2hex;
use function hash;
use function json_encode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesMatchBundleContent */
final class TransparencyLogEntriesMatchBundleContentTest extends TestCase
{
    private const CERTIFICATE_DER_BYTES       = 'a certificate, as raw DER bytes';
    private const OTHER_CERTIFICATE_DER_BYTES = 'a different certificate, as raw DER bytes';
    private const SIGNATURE_BYTES             = 'a signature, as raw bytes';
    private const OTHER_SIGNATURE_BYTES       = 'a different signature, as raw bytes';

    private static function pemFromDerBytes(string $derBytes): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . base64_encode($derBytes) . "\n-----END CERTIFICATE-----\n";
    }

    private static function check(): TransparencyLogEntriesMatchBundleContent
    {
        return new TransparencyLogEntriesMatchBundleContent();
    }

    /** @param non-empty-string $digestHex */
    private static function assertOnBundle(Bundle $bundle, string $digestHex): void
    {
        self::check()->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', $digestHex), 0, $bundle);
    }

    /** @param non-empty-string $digestHex */
    private static function hashedRekordV001Bundle(
        string $digestHex,
        string $entrySignatureBytes,
        string $entryCertificateDerBytes,
        string $messageSignatureBytes,
        string $certificateDerBytes,
    ): Bundle {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode($certificateDerBytes)],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
                        'logId' => ['keyId' => base64_encode('not a real log id')],
                        'canonicalizedBody' => base64_encode((string) json_encode([
                            'spec' => [
                                'data' => ['hash' => ['value' => $digestHex]],
                                'signature' => [
                                    'content' => base64_encode($entrySignatureBytes),
                                    'publicKey' => ['content' => base64_encode(self::pemFromDerBytes($entryCertificateDerBytes))],
                                ],
                            ],
                        ])),
                    ],
                ],
            ],
            'messageSignature' => [
                'messageDigest' => ['algorithm' => 'SHA2_256', 'digest' => base64_encode('not a real digest')],
                'signature' => base64_encode($messageSignatureBytes),
            ],
        ]);
    }

    private static function hashedRekordV002Bundle(
        string $digestBytes,
        string $entrySignatureBytes,
        string $entryCertificateDerBytes,
        string $messageSignatureBytes,
        string $certificateDerBytes,
    ): Bundle {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode($certificateDerBytes)],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.2'],
                        'logId' => ['keyId' => base64_encode('not a real log id')],
                        'canonicalizedBody' => base64_encode((string) json_encode([
                            'spec' => [
                                'hashedRekordV002' => [
                                    'data' => ['digest' => base64_encode($digestBytes)],
                                    'signature' => [
                                        'content' => base64_encode($entrySignatureBytes),
                                        'verifier' => ['x509Certificate' => ['rawBytes' => base64_encode($entryCertificateDerBytes)]],
                                    ],
                                ],
                            ],
                        ])),
                    ],
                ],
            ],
            'messageSignature' => [
                'messageDigest' => ['algorithm' => 'SHA2_256', 'digest' => base64_encode('not a real digest')],
                'signature' => base64_encode($messageSignatureBytes),
            ],
        ]);
    }

    private static function dsseBundle(
        string $payload,
        string $entryPayloadHashHex,
        string $entrySignatureBytes,
        string $entryCertificateDerBytes,
        string $envelopeSignatureBytes,
        string $certificateDerBytes,
    ): Bundle {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode($certificateDerBytes)],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'kindVersion' => ['kind' => 'dsse', 'version' => '0.0.1'],
                        'logId' => ['keyId' => base64_encode('not a real log id')],
                        'canonicalizedBody' => base64_encode((string) json_encode([
                            'spec' => [
                                'payloadHash' => ['value' => $entryPayloadHashHex],
                                'signatures' => [
                                    [
                                        'signature' => base64_encode($entrySignatureBytes),
                                        'verifier' => base64_encode(self::pemFromDerBytes($entryCertificateDerBytes)),
                                    ],
                                ],
                            ],
                        ])),
                    ],
                ],
            ],
            'dsseEnvelope' => [
                'payload' => base64_encode($payload),
                'payloadType' => 'application/vnd.in-toto+json',
                'signatures' => [['sig' => base64_encode($envelopeSignatureBytes)]],
            ],
        ]);
    }

    private static function intotoBundle(
        string $payload,
        string $entryPayloadHashHex,
        string $entrySignatureBytes,
        string $entryCertificateDerBytes,
        string $envelopeSignatureBytes,
        string $certificateDerBytes,
    ): Bundle {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode($certificateDerBytes)],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'kindVersion' => ['kind' => 'intoto', 'version' => '0.0.2'],
                        'logId' => ['keyId' => base64_encode('not a real log id')],
                        'canonicalizedBody' => base64_encode((string) json_encode([
                            'spec' => [
                                'content' => [
                                    'payloadHash' => ['value' => $entryPayloadHashHex],
                                    'envelope' => [
                                        'signatures' => [
                                            [
                                                'sig' => base64_encode(base64_encode($entrySignatureBytes)),
                                                'publicKey' => base64_encode(self::pemFromDerBytes($entryCertificateDerBytes)),
                                            ],
                                        ],
                                    ],
                                ],
                            ],
                        ])),
                    ],
                ],
            ],
            'dsseEnvelope' => [
                'payload' => base64_encode($payload),
                'payloadType' => 'application/vnd.in-toto+json',
                'signatures' => [['sig' => base64_encode($envelopeSignatureBytes)]],
            ],
        ]);
    }

    public function testAcceptsAMatchingHashedRekordV001Entry(): void
    {
        $digestHex = bin2hex('a digest');
        $bundle    = self::hashedRekordV001Bundle($digestHex, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectNotToPerformAssertions();
        self::assertOnBundle($bundle, $digestHex);
    }

    public function testRejectsAHashedRekordV001EntryWithAMismatchedDigest(): void
    {
        $digestHex = bin2hex('a digest');
        $bundle    = self::hashedRekordV001Bundle($digestHex, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(DigestMismatch::class);
        self::assertOnBundle($bundle, bin2hex('a different digest'));
    }

    public function testRejectsAHashedRekordV001EntryWithAMismatchedSignature(): void
    {
        $digestHex = bin2hex('a digest');
        $bundle    = self::hashedRekordV001Bundle($digestHex, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::OTHER_SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, $digestHex);
    }

    public function testRejectsAHashedRekordV001EntryWithAMismatchedCertificate(): void
    {
        $digestHex = bin2hex('a digest');
        $bundle    = self::hashedRekordV001Bundle($digestHex, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::OTHER_CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, $digestHex);
    }

    public function testAcceptsAMatchingHashedRekordV002Entry(): void
    {
        $digestBytes = 'a digest';
        $bundle      = self::hashedRekordV002Bundle($digestBytes, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectNotToPerformAssertions();
        self::assertOnBundle($bundle, bin2hex($digestBytes));
    }

    public function testRejectsAHashedRekordV002EntryWithAMismatchedDigest(): void
    {
        $digestBytes = 'a digest';
        $bundle      = self::hashedRekordV002Bundle($digestBytes, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(DigestMismatch::class);
        self::assertOnBundle($bundle, bin2hex('a different digest'));
    }

    public function testAcceptsAMatchingDsseEntry(): void
    {
        $payload = 'a dsse payload';
        $bundle  = self::dsseBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectNotToPerformAssertions();
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsADsseEntryWithAMismatchedPayloadHash(): void
    {
        $payload = 'a dsse payload';
        $bundle  = self::dsseBundle($payload, hash('sha256', 'a different payload'), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(DigestMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsADsseEntryWithAMismatchedSignature(): void
    {
        $payload = 'a dsse payload';
        $bundle  = self::dsseBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::OTHER_SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsADsseEntryWithAMismatchedCertificate(): void
    {
        $payload = 'a dsse payload';
        $bundle  = self::dsseBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::OTHER_CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testAcceptsAMatchingIntotoEntry(): void
    {
        $payload = 'an intoto payload';
        $bundle  = self::intotoBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectNotToPerformAssertions();
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsAnIntotoEntryWithAMismatchedPayloadHash(): void
    {
        $payload = 'an intoto payload';
        $bundle  = self::intotoBundle($payload, hash('sha256', 'a different payload'), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(DigestMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsAnIntotoEntryWithAMismatchedSignature(): void
    {
        $payload = 'an intoto payload';
        $bundle  = self::intotoBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::OTHER_SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }

    public function testRejectsAnIntotoEntryWithAMismatchedCertificate(): void
    {
        $payload = 'an intoto payload';
        $bundle  = self::intotoBundle($payload, hash('sha256', $payload), self::SIGNATURE_BYTES, self::CERTIFICATE_DER_BYTES, self::SIGNATURE_BYTES, self::OTHER_CERTIFICATE_DER_BYTES);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        self::assertOnBundle($bundle, 'irrelevant');
    }
}

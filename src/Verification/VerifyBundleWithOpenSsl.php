<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\PemPublicKey;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\CertificateIdentityMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointKeyHintMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointSignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidCheckpointFormat;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidDerEncodedStringLength;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidIntegratedTime;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidLogIndex;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidMerkleInclusionProof;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\NoTransparencyLogKeyInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleMediaType;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedTransparencyLogKeyAlgorithm;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function array_map;
use function array_search;
use function array_slice;
use function base64_decode;
use function bin2hex;
use function count;
use function explode;
use function extension_loaded;
use function file_get_contents;
use function hash;
use function hash_equals;
use function implode;
use function in_array;
use function is_array;
use function is_readable;
use function is_string;
use function json_decode;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_parse;
use function openssl_x509_verify;
use function ord;
use function sodium_crypto_sign_verify_detached;
use function strlen;
use function substr;
use function trim;

use const OPENSSL_ALGO_SHA256;

class VerifyBundleWithOpenSsl implements VerifyBundle
{
    public const TRUSTED_ROOT_FILE_PATH = __DIR__ . '/../../resources/trusted-root.jsonl';

    private const SUPPORTED_BUNDLE_MEDIA_TYPES = [
        'application/vnd.dev.sigstore.bundle+json;version=0.1',
        'application/vnd.dev.sigstore.bundle+json;version=0.2',
        'application/vnd.dev.sigstore.bundle+json;version=0.3',
        'application/vnd.dev.sigstore.bundle.v0.3+json',
    ];

    private const KEY_DETAILS_ECDSA_P256_SHA_256 = 'PKIX_ECDSA_P256_SHA_256';
    private const KEY_DETAILS_ED25519            = 'PKIX_ED25519';

    private const SUPPORTED_TRANSPARENCY_LOG_KEY_DETAILS = [
        self::KEY_DETAILS_ECDSA_P256_SHA_256,
        self::KEY_DETAILS_ED25519,
    ];

    private const ED25519_SPKI_DER_PREFIX_LENGTH = 12;
    private const ED25519_RAW_PUBLIC_KEY_LENGTH  = 32;

    /** @var non-empty-string */
    private string $trustedRootFilePath;

    /** @param non-empty-string $trustedRootFilePath */
    public function __construct(string $trustedRootFilePath)
    {
        Assert::fileExists($trustedRootFilePath);
        $this->trustedRootFilePath = $trustedRootFilePath;
    }

    public static function factory(): self
    {
        return new self(self::TRUSTED_ROOT_FILE_PATH);
    }

    /** @inheritDoc */
    public function verify(
        array $bundles,
        FilenameWithChecksum $file,
        ?string $expectedSubjectName,
        array $extensionsToVerify,
        string $expectedCertificateIdentity
    ): void {
        foreach ($bundles as $bundleIndex => $bundle) {
            /**
             * Useful references. Whilst we don't do the full verification that
             * `gh attestation verify` would (since we don't want to re-invent
             * the wheel), we can do some basic check of the DSSE Envelope.
             * We'll check the payload digest matches our expectation, and
             * verify the signature with the certificate.
             *
             *  - https://github.com/cli/cli/blob/234d2effd545fb9d72ea77aa648caa499aecaa6e/pkg/cmd/attestation/verify/verify.go#L225-L256
             *  - https://docs.sigstore.dev/logging/verify-release/
             *  - https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#protocol
             */
            $this->assertBundleMediaTypeIsSupported($bundle);

            $this->assertTransparencyLogEntriesHaveValidLogIndex($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesAreWithinCertificateValidity($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesHaveValidInclusionProof($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesHaveValidCheckpoints($bundleIndex, $bundle);

            $this->assertCertificateSignedByTrustedRoot($bundle);

            $this->assertCertificateExtensionClaims($bundle, $extensionsToVerify);

            $this->assertCertificateIdentity($bundle, $expectedCertificateIdentity);

            if ($bundle->content() instanceof DsseEnvelope) {
                $this->assertDigestFromAttestationMatchesActual($file, $expectedSubjectName, $bundle->content());
                $this->verifyDsseEnvelopeSignature($bundleIndex, $bundle->certificate(), $bundle->content());
            } elseif ($bundle->content() instanceof MessageSignature) {
                $this->assertDigestFromMessageSignatureMatchesActual($file, $bundle->content());
                $this->verifyMessageSignature($bundleIndex, $file, $bundle->certificate(), $bundle->content());
            } else {
                throw UnsupportedBundleContent::new();
            }
        }
    }

    private function assertBundleMediaTypeIsSupported(Bundle $bundle): void
    {
        if (! in_array($bundle->mediaType(), self::SUPPORTED_BUNDLE_MEDIA_TYPES, true)) {
            throw UnsupportedBundleMediaType::fromMediaType($bundle->mediaType());
        }
    }

    private function assertTransparencyLogEntriesHaveValidLogIndex(int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->logIndex() < 0) {
                throw InvalidLogIndex::forIndex($bundleIndex, $transparencyLogEntry->logIndex());
            }
        }
    }

    private function assertTransparencyLogEntriesAreWithinCertificateValidity(int $bundleIndex, Bundle $bundle): void
    {
        if ($bundle->transparencyLogEntries() === []) {
            return;
        }

        $certificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($certificateInfo);
        Assert::keyExists($certificateInfo, 'validFrom_time_t');
        Assert::integer($certificateInfo['validFrom_time_t']);
        Assert::keyExists($certificateInfo, 'validTo_time_t');
        Assert::integer($certificateInfo['validTo_time_t']);

        $certificateValidFrom = $certificateInfo['validFrom_time_t'];
        $certificateValidTo   = $certificateInfo['validTo_time_t'];

        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->integratedTime() === null) {
                continue;
            }

            if (
                $transparencyLogEntry->integratedTime() < $certificateValidFrom
                || $transparencyLogEntry->integratedTime() > $certificateValidTo
            ) {
                throw InvalidIntegratedTime::forIndex(
                    $bundleIndex,
                    $transparencyLogEntry->integratedTime(),
                    $certificateValidFrom,
                    $certificateValidTo,
                );
            }
        }
    }

    /**
     * @link https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1
     * @link https://github.com/transparency-dev/merkle/blob/main/proof/verify.go
     */
    private function assertTransparencyLogEntriesHaveValidInclusionProof(int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $inclusionProof = $transparencyLogEntry->inclusionProof();
            if ($inclusionProof === null) {
                continue;
            }

            $index = $inclusionProof->logIndex();
            $size  = $inclusionProof->treeSize();
            $proof = $inclusionProof->hashes();

            $inner  = $this->bitLength($index ^ $size - 1);
            $border = $this->popCount($index >> $inner);

            if (count($proof) !== $inner + $border) {
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
            }

            $seed = $this->merkleLeafHash($transparencyLogEntry->canonicalizedBody());
            for ($i = 0; $i < $inner; $i++) {
                if ((($index >> $i) & 1) === 0) {
                    $seed = $this->merkleNodeHash($seed, $proof[$i]);
                } else {
                    $seed = $this->merkleNodeHash($proof[$i], $seed);
                }
            }

            for ($i = $inner; $i < count($proof); $i++) {
                $seed = $this->merkleNodeHash($proof[$i], $seed);
            }

            if (! hash_equals($inclusionProof->rootHash(), $seed)) {
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
            }
        }
    }

    private function merkleLeafHash(string $canonicalizedBody): string
    {
        return hash('sha256', "\x00" . $canonicalizedBody, true);
    }

    private function merkleNodeHash(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    private function bitLength(int $n): int
    {
        $length = 0;
        while ($n > 0) {
            $n >>= 1;
            $length++;
        }

        return $length;
    }

    private function popCount(int $n): int
    {
        $count = 0;
        while ($n > 0) {
            $count += $n & 1;
            $n    >>= 1;
        }

        return $count;
    }

    /**
     * @link https://github.com/sigstore/rekor/blob/main/pkg/util/checkpoint.go
     * @link https://github.com/sigstore/rekor/blob/main/pkg/util/signed_note.go
     */
    private function assertTransparencyLogEntriesHaveValidCheckpoints(int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $inclusionProof = $transparencyLogEntry->inclusionProof();
            if ($inclusionProof === null) {
                continue;
            }

            $checkpointEnvelope = $inclusionProof->checkpointEnvelope();
            if ($checkpointEnvelope === null) {
                continue;
            }

            $parsedCheckpoint = $this->parseCheckpointEnvelope($bundleIndex, $checkpointEnvelope);

            $transparencyLogKey = $this->resolveTransparencyLogPublicKey($transparencyLogEntry->logId());

            if (! hash_equals(substr($transparencyLogKey['keyId'], 0, 4), $parsedCheckpoint['keyHint'])) {
                throw CheckpointKeyHintMismatch::forIndex($bundleIndex);
            }

            if (
                ! $this->verifyTransparencyLogSignature(
                    $transparencyLogKey,
                    $parsedCheckpoint['noteText'],
                    $parsedCheckpoint['signature'],
                )
            ) {
                throw CheckpointSignatureVerificationFailed::forIndex($bundleIndex);
            }
        }
    }

    /**
     * @param array{publicKey: PemPublicKey, keyId: non-empty-string, keyDetails: non-empty-string} $transparencyLogKey
     * @param non-empty-string                                                                      $signedContent
     * @param non-empty-string                                                                      $signature
     */
    private function verifyTransparencyLogSignature(array $transparencyLogKey, string $signedContent, string $signature): bool
    {
        if ($transparencyLogKey['keyDetails'] === self::KEY_DETAILS_ED25519) {
            return sodium_crypto_sign_verify_detached(
                $signature,
                $signedContent,
                $this->extractRawEd25519PublicKey($transparencyLogKey['publicKey']),
            );
        }

        $publicKey = openssl_pkey_get_public($transparencyLogKey['publicKey']->decoratedPublicKey());
        Assert::notFalse($publicKey);

        return openssl_verify($signedContent, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /** @return non-empty-string */
    private function extractRawEd25519PublicKey(PemPublicKey $publicKey): string
    {
        $derEncodedBytes = $publicKey->derEncodedBytes();
        Assert::same(strlen($derEncodedBytes), self::ED25519_SPKI_DER_PREFIX_LENGTH + self::ED25519_RAW_PUBLIC_KEY_LENGTH);

        return substr($derEncodedBytes, -self::ED25519_RAW_PUBLIC_KEY_LENGTH);
    }

    /** @return array{noteText: non-empty-string, keyHint: non-empty-string, signature: non-empty-string} */
    private function parseCheckpointEnvelope(int $bundleIndex, string $envelope): array
    {
        $lines          = explode("\n", $envelope);
        $blankLineIndex = array_search('', $lines, true);

        if (
            $blankLineIndex === false
            || ! isset($lines[$blankLineIndex + 1])
            || $lines[$blankLineIndex + 1] === ''
        ) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $noteText = implode("\n", array_slice($lines, 0, $blankLineIndex)) . "\n";

        $signatureLineParts = explode(' ', $lines[$blankLineIndex + 1], 3);
        if (count($signatureLineParts) !== 3) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $signatureBlob = base64_decode($signatureLineParts[2]);
        if ($signatureBlob === '' || strlen($signatureBlob) <= 4) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $signature = substr($signatureBlob, 4);
        Assert::stringNotEmpty($signature);

        return [
            'noteText' => $noteText,
            'keyHint' => substr($signatureBlob, 0, 4),
            'signature' => $signature,
        ];
    }

    private function assertCertificateSignedByTrustedRoot(Bundle $bundle): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'issuer');
        if (is_array($attestationCertificateInfo['issuer'])) {
            Assert::allStringNotEmpty($attestationCertificateInfo['issuer']);
        } else {
            Assert::stringNotEmpty($attestationCertificateInfo['issuer']);
        }

        $trustedRootCert = file_get_contents($this->trustedRootFilePath);
        Assert::stringNotEmpty($trustedRootCert);
        $trustedRootJsonLines = explode("\n", trim($trustedRootCert));

        /**
         * Now go through our trusted root certificates and attempt to verify that the certificate was signed by an
         * in-date trusted root certificate. The root certificates should be periodically and frequently updated using:
         *
         *     gh attestation trusted-root > resources/trusted-root.jsonl
         *
         * And verifying the contents afterwards to ensure they have not been compromised. This list of JSON blobs may
         * have multiple certificates (e.g. root certificates, intermediate certificates, expired certificates, etc.)
         * so we should loop over to find the correct certificate used to sign the attestation certificate.
         */
        foreach ($trustedRootJsonLines as $jsonLine) {
            /** @var mixed $decoded */
            $decoded = json_decode($jsonLine, true);

            // No certificate authorities defined in this JSON line, skip it...
            if (
                ! is_array($decoded)
                || ! array_key_exists('certificateAuthorities', $decoded)
                || ! is_array($decoded['certificateAuthorities'])
            ) {
                continue;
            }

            /** @var mixed $certificateAuthority */
            foreach ($decoded['certificateAuthorities'] as $certificateAuthority) {
                // We don't have a certificate chain defined, skip it...
                if (
                    ! is_array($certificateAuthority)
                    || ! array_key_exists('certChain', $certificateAuthority)
                    || ! is_array($certificateAuthority['certChain'])
                    || ! array_key_exists('certificates', $certificateAuthority['certChain'])
                    || ! is_array($certificateAuthority['certChain']['certificates'])
                ) {
                    continue;
                }

                /** @var mixed $caCertificateWrapper */
                foreach ($certificateAuthority['certChain']['certificates'] as $caCertificateWrapper) {
                    // Certificate is not in the expected format, i.e. no rawBytes key, skip it...
                    if (
                        ! is_array($caCertificateWrapper)
                        || ! array_key_exists('rawBytes', $caCertificateWrapper)
                        || ! is_string($caCertificateWrapper['rawBytes'])
                        || $caCertificateWrapper['rawBytes'] === ''
                    ) {
                        continue;
                    }

                    $caCertificateString = PemCertificate::fromBase64EncodedDerBytes(
                        $caCertificateWrapper['rawBytes'],
                    )->decoratedCertificate();

                    $caCertificateInfo = openssl_x509_parse($caCertificateString);
                    Assert::isArray($caCertificateInfo);
                    Assert::keyExists($caCertificateInfo, 'subject');

                    // If the CA certificate subject is not the issuer of the attestation certificate,
                    // this was not the cert we were looking for, skip it...
                    if ($caCertificateInfo['subject'] !== $attestationCertificateInfo['issuer']) {
                        continue;
                    }

                    // Finally, verify that the located CA cert was used to sign the attestation certificate
                    if (openssl_x509_verify($bundle->certificate()->decoratedCertificate(), $caCertificateString) !== 1) {
                        /** @psalm-suppress MixedArgument */
                        throw IssuerCertificateVerificationFailed::fromIssuer($attestationCertificateInfo['issuer']);
                    }

                    return;
                }
            }
        }

        /**
         * If we got here, we skipped all the certificates in the trusted root collection for various reasons; so we
         * therefore cannot trust the attestation certificate.
         *
         * @psalm-suppress MixedArgument
         */
        throw NoIssuerCertificateInTrustedRoot::fromIssuer($attestationCertificateInfo['issuer']);
    }

    /**
     * @param non-empty-string $logId
     *
     * @return array{publicKey: PemPublicKey, keyId: non-empty-string, keyDetails: non-empty-string}
     */
    private function resolveTransparencyLogPublicKey(string $logId): array
    {
        $trustedRootCert = file_get_contents($this->trustedRootFilePath);
        Assert::stringNotEmpty($trustedRootCert);
        $trustedRootJsonLines = explode("\n", trim($trustedRootCert));

        foreach ($trustedRootJsonLines as $jsonLine) {
            /** @var mixed $decoded */
            $decoded = json_decode($jsonLine, true);

            // No transparency logs defined in this JSON line, skip it...
            if (
                ! is_array($decoded)
                || ! array_key_exists('tlogs', $decoded)
                || ! is_array($decoded['tlogs'])
            ) {
                continue;
            }

            /** @var mixed $tlog */
            foreach ($decoded['tlogs'] as $tlog) {
                // Not in the expected shape, skip it...
                if (
                    ! is_array($tlog)
                    || ! array_key_exists('logId', $tlog)
                    || ! is_array($tlog['logId'])
                    || ! array_key_exists('keyId', $tlog['logId'])
                    || ! is_string($tlog['logId']['keyId'])
                    || $tlog['logId']['keyId'] === ''
                    || ! array_key_exists('publicKey', $tlog)
                    || ! is_array($tlog['publicKey'])
                    || ! array_key_exists('rawBytes', $tlog['publicKey'])
                    || ! is_string($tlog['publicKey']['rawBytes'])
                    || $tlog['publicKey']['rawBytes'] === ''
                    || ! array_key_exists('keyDetails', $tlog['publicKey'])
                    || ! is_string($tlog['publicKey']['keyDetails'])
                    || $tlog['publicKey']['keyDetails'] === ''
                ) {
                    continue;
                }

                $tlogKeyId = base64_decode($tlog['logId']['keyId']);
                if ($tlogKeyId === '' || ! hash_equals($logId, $tlogKeyId)) {
                    continue;
                }

                if (! in_array($tlog['publicKey']['keyDetails'], self::SUPPORTED_TRANSPARENCY_LOG_KEY_DETAILS, true)) {
                    throw UnsupportedTransparencyLogKeyAlgorithm::fromKeyDetails($tlog['publicKey']['keyDetails']);
                }

                return [
                    'publicKey' => PemPublicKey::fromBase64EncodedDerBytes($tlog['publicKey']['rawBytes']),
                    'keyId' => $tlogKeyId,
                    'keyDetails' => $tlog['publicKey']['keyDetails'],
                ];
            }
        }

        throw NoTransparencyLogKeyInTrustedRoot::fromLogId(bin2hex($logId));
    }

    /** @param array<non-empty-string, string> $extensions */
    private function assertCertificateExtensionClaims(Bundle $bundle, array $extensions): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'extensions');
        Assert::isArray($attestationCertificateInfo['extensions']);

        /**
         * See {@link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#136141572641--fulcio} for details
         * on the Fulcio extension keys; note the values are DER-encoded strings; the ASN.1 tag is UTF8String (0x0C).
         *
         * Check the extension values are what we expect; these are hard-coded, as we don't expect them
         * to change unless the namespace/repo name change, etc.
         */
        foreach ($extensions as $extension => $expectedValue) {
            Assert::keyExists($attestationCertificateInfo['extensions'], $extension);
            Assert::stringNotEmpty($attestationCertificateInfo['extensions'][$extension]);
            $actualValue = $attestationCertificateInfo['extensions'][$extension];

            // First character (the ASN.1 tag) is expected to be UTF8String (0x0C)
            if (ord($actualValue[0]) !== 0x0C) {
                throw MismatchingExtensionValues::from($extension, $expectedValue, $actualValue);
            }

            /**
             * Second character is expected to be the length of the actual value
             * as long as they are less than 127 bytes (short form)
             *
             * @link https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html#Lengths
             */
            $expectedValueLength = ord($actualValue[1]);
            if (strlen($actualValue) !== 2 + $expectedValueLength) {
                throw InvalidDerEncodedStringLength::fromDerString($actualValue, 2 + $expectedValueLength);
            }

            $derDecodedValue = substr($actualValue, 2, $expectedValueLength);
            if ($derDecodedValue !== $expectedValue) {
                throw MismatchingExtensionValues::from($extension, $expectedValue, $derDecodedValue);
            }
        }
    }

    private function assertCertificateIdentity(Bundle $bundle, string $expectedCertificateIdentity): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'extensions');
        Assert::isArray($attestationCertificateInfo['extensions']);
        Assert::keyExists($attestationCertificateInfo['extensions'], 'subjectAltName');
        Assert::stringNotEmpty($attestationCertificateInfo['extensions']['subjectAltName']);

        $subjectAltName = $attestationCertificateInfo['extensions']['subjectAltName'];

        $identities = array_map(
            static function (string $entry): string {
                $parts = explode(':', trim($entry), 2);

                return $parts[1] ?? $parts[0];
            },
            explode(',', $subjectAltName),
        );

        if (! in_array($expectedCertificateIdentity, $identities, true)) {
            throw CertificateIdentityMismatch::from($expectedCertificateIdentity, $subjectAltName);
        }
    }

    private function verifyDsseEnvelopeSignature(int $bundleIndex, PemCertificate $certificate, DsseEnvelope $envelope): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (
            openssl_verify(
                $envelope->preAuthenticationEncoding(),
                $envelope->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    /**
     * This requires the artifact on disk to verify the signature. A digest-only verification is specifically not
     * supported, as there's nothing to verify against.
     */
    private function verifyMessageSignature(int $bundleIndex, FilenameWithChecksum $file, PemCertificate $certificate, MessageSignature $content): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        if (! is_readable($file->filename())) {
            throw CannotVerifyMessageSignatureWithoutArtifact::new();
        }

        $artifactContents = file_get_contents($file->filename());
        Assert::stringNotEmpty($artifactContents);

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (
            openssl_verify(
                $artifactContents,
                $content->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    private function assertDigestFromMessageSignatureMatchesActual(FilenameWithChecksum $file, MessageSignature $content): void
    {
        $expected = $file->checksum();
        $actual   = $content->digestHex();
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }

    /** @param non-empty-string|null $expectedSubjectName */
    private function assertDigestFromAttestationMatchesActual(FilenameWithChecksum $file, ?string $expectedSubjectName, DsseEnvelope $envelope): void
    {
        /** @var mixed $decodedPayload */
        $decodedPayload = json_decode($envelope->payload(), true);

        if (
            ! is_array($decodedPayload)
            || ! array_key_exists('subject', $decodedPayload)
            || ! is_array($decodedPayload['subject'])
            || count($decodedPayload['subject']) !== 1
            || ! array_key_exists(0, $decodedPayload['subject'])
            || ! is_array($decodedPayload['subject'][0])
            || ! array_key_exists('name', $decodedPayload['subject'][0])
            || ($expectedSubjectName !== null && $decodedPayload['subject'][0]['name'] !== $expectedSubjectName)
            || ! array_key_exists('digest', $decodedPayload['subject'][0])
            || ! is_array($decodedPayload['subject'][0]['digest'])
            || ! array_key_exists('sha256', $decodedPayload['subject'][0]['digest'])
            || ! is_string($decodedPayload['subject'][0]['digest']['sha256'])
            || $decodedPayload['subject'][0]['digest']['sha256'] === ''
        ) {
            throw InvalidSubjectDefinition::new();
        }

        $expected = $file->checksum();
        $actual   = $decodedPayload['subject'][0]['digest']['sha256'];
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\PemPublicKey;
use ThePhpFoundation\Attestation\TransparencyLogEntry;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported;
use ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex;
use ThePhpFoundation\Attestation\Verification\Assertion\VerifyBundleCheck;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\CertificateIdentityMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointKeyHintMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointRootHashMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointSignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidCheckpointFormat;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidDerEncodedStringLength;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidMerkleInclusionProof;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\SignedEntryTimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogEntryContentMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function array_map;
use function array_search;
use function array_slice;
use function base64_decode;
use function base64_encode;
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
use function json_encode;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_parse;
use function openssl_x509_verify;
use function ord;
use function sodium_crypto_sign_verify_detached;
use function strlen;
use function substr;
use function trim;

use const JSON_UNESCAPED_SLASHES;
use const OPENSSL_ALGO_SHA256;

/** @phpstan-type TransparencyLogKey array{publicKey: PemPublicKey, keyId: non-empty-string, keyDetails: non-empty-string, validFor: array{start: int, end: int|null}} */
class VerifyBundleWithOpenSsl implements VerifyBundle
{
    public const TRUSTED_ROOT_FILE_PATH = __DIR__ . '/../../resources/trusted-root.jsonl';

    private const ED25519_SPKI_DER_PREFIX_LENGTH = 12;
    private const ED25519_RAW_PUBLIC_KEY_LENGTH  = 32;

    private const HASHEDREKORD_VERSION_0_0_2 = '0.0.2';

    /** @link https://www.rfc-editor.org/rfc/rfc6962#section-3.3 */
    private const CT_PRECERT_SCTS_EXTENSION_OID_DER = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";

    private TrustedRoot $trustedRoot;

    /** @var list<VerifyBundleCheck> */
    private array $checks;

    /** @param list<VerifyBundleCheck> $checks */
    public function __construct(TrustedRoot $trustedRoot, array $checks)
    {
        $this->trustedRoot = $trustedRoot;
        $this->checks      = $checks;
    }

    public static function factory(): self
    {
        return self::withTrustedRootFile(self::TRUSTED_ROOT_FILE_PATH);
    }

    /** @param non-empty-string $trustedRootFilePath */
    public static function withTrustedRootFile(string $trustedRootFilePath): self
    {
        $trustedRoot = new TrustedRoot($trustedRootFilePath);

        return new self($trustedRoot, self::defaultChecks($trustedRoot));
    }

    /** @return list<VerifyBundleCheck> */
    private static function defaultChecks(TrustedRoot $trustedRoot): array
    {
        return [
            new BundleMediaTypeIsSupported(),
            new TransparencyLogEntriesHaveValidLogIndex(),
            new TransparencyLogEntriesAreWithinCertificateValidity(),
            new TransparencyLogEntriesAreWithinTransparencyLogKeyValidity($trustedRoot),
            new Rfc3161TimestampsAreValid($trustedRoot),
        ];
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
            foreach ($this->checks as $check) {
                $check->assert($file, $bundleIndex, $bundle);
            }

            $this->assertTransparencyLogEntriesHaveValidInclusionProof($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesHaveValidCheckpoints($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesHaveValidSignedEntryTimestamps($bundleIndex, $bundle);

            $this->assertTransparencyLogEntriesMatchBundleContent($bundleIndex, $bundle, $file);

            $this->assertCertificateSignedByTrustedRoot($bundle);

            $this->assertCertificateHasATrustedSignedCertificateTimestamp($bundle);

            $this->assertCertificateExtensionClaims($bundle, $extensionsToVerify);

            $this->assertCertificateIdentity($bundle, $expectedCertificateIdentity);

            if ($bundle->content() instanceof DsseEnvelope) {
                $this->assertDigestFromAttestationMatchesActual($file, $bundle->content());
                $this->verifyDsseEnvelopeSignature($bundleIndex, $bundle->certificate(), $bundle->content());
            } elseif ($bundle->content() instanceof MessageSignature) {
                $this->assertDigestFromMessageSignatureMatchesActual($file, $bundle->content());
                $this->verifyMessageSignature($bundleIndex, $file, $bundle->certificate(), $bundle->content());
            } else {
                throw UnsupportedBundleContent::new();
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
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
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

            $transparencyLogKey = $this->trustedRoot->resolveTransparencyLogPublicKey($transparencyLogEntry->logId());

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

            if (! hash_equals($inclusionProof->rootHash(), $parsedCheckpoint['rootHash'])) {
                throw CheckpointRootHashMismatch::forIndex($bundleIndex);
            }
        }
    }

    /** @link https://github.com/sigstore/rekor/blob/main/pkg/util/signed_note.go */
    private function assertTransparencyLogEntriesHaveValidSignedEntryTimestamps(int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $signedEntryTimestamp = $transparencyLogEntry->signedEntryTimestamp();
            $integratedTime       = $transparencyLogEntry->integratedTime();
            if ($signedEntryTimestamp === null || $integratedTime === null) {
                continue;
            }

            $transparencyLogKey = $this->trustedRoot->resolveTransparencyLogPublicKey($transparencyLogEntry->logId());

            $signedContent = json_encode(
                [
                    'body' => base64_encode($transparencyLogEntry->canonicalizedBody()),
                    'integratedTime' => $integratedTime,
                    'logID' => bin2hex($transparencyLogEntry->logId()),
                    'logIndex' => $transparencyLogEntry->logIndex(),
                ],
                JSON_UNESCAPED_SLASHES,
            );
            Assert::stringNotEmpty($signedContent);

            if (! $this->verifyTransparencyLogSignature($transparencyLogKey, $signedContent, $signedEntryTimestamp)) {
                throw SignedEntryTimestampVerificationFailed::forIndex($bundleIndex);
            }
        }
    }

    private function assertTransparencyLogEntriesMatchBundleContent(int $bundleIndex, Bundle $bundle, FilenameWithChecksum $file): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->kind() === 'hashedrekord' && $bundle->content() instanceof MessageSignature) {
                $this->assertHashedRekordEntryMatchesBundleContent(
                    $bundleIndex,
                    $transparencyLogEntry,
                    $file,
                    $bundle->content(),
                    $bundle->certificate(),
                );
            } elseif ($transparencyLogEntry->kind() === 'dsse' && $bundle->content() instanceof DsseEnvelope) {
                $this->assertDsseEntryMatchesBundleContent(
                    $bundleIndex,
                    $transparencyLogEntry,
                    $bundle->content(),
                    $bundle->certificate(),
                );
            } elseif ($transparencyLogEntry->kind() === 'intoto' && $bundle->content() instanceof DsseEnvelope) {
                $this->assertIntotoEntryMatchesBundleContent(
                    $bundleIndex,
                    $transparencyLogEntry,
                    $bundle->content(),
                    $bundle->certificate(),
                );
            }
        }
    }

    private function assertHashedRekordEntryMatchesBundleContent(
        int $bundleIndex,
        TransparencyLogEntry $transparencyLogEntry,
        FilenameWithChecksum $file,
        MessageSignature $content,
        PemCertificate $certificate
    ): void {
        /** @var array<array-key, mixed> $body */
        $body = json_decode($transparencyLogEntry->canonicalizedBody(), true);
        Assert::isArray($body['spec']);

        [$entryDigestHex, $entrySignatureContent, $entryCertificateDer] = $transparencyLogEntry->version() === self::HASHEDREKORD_VERSION_0_0_2
            ? $this->parseHashedRekordV002Spec($body['spec'])
            : $this->parseHashedRekordV001Spec($body['spec']);

        if (! hash_equals($file->checksum(), $entryDigestHex)) {
            throw DigestMismatch::fromChecksumMismatch($file->checksum(), $entryDigestHex);
        }

        $entrySignature = base64_decode($entrySignatureContent);
        Assert::stringNotEmpty($entrySignature);

        if (! hash_equals($content->signature(), $entrySignature)) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'signature');
        }

        if (! hash_equals($certificate->derEncodedBytes(), $entryCertificateDer)) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'certificate');
        }
    }

    /**
     * @param array<array-key, mixed> $spec
     *
     * @return array{0: non-empty-string, 1: non-empty-string, 2: non-empty-string} [digestHex, base64-encoded signature, DER-encoded certificate]
     */
    private function parseHashedRekordV001Spec(array $spec): array
    {
        Assert::isArray($spec['data']);
        Assert::isArray($spec['data']['hash']);
        Assert::stringNotEmpty($spec['data']['hash']['value']);

        Assert::isArray($spec['signature']);
        Assert::stringNotEmpty($spec['signature']['content']);

        Assert::isArray($spec['signature']['publicKey']);
        Assert::stringNotEmpty($spec['signature']['publicKey']['content']);
        $certificatePem = base64_decode($spec['signature']['publicKey']['content']);
        Assert::stringNotEmpty($certificatePem);

        return [
            $spec['data']['hash']['value'],
            $spec['signature']['content'],
            Der::bytesFromPem($certificatePem),
        ];
    }

    /**
     * @param array<array-key, mixed> $spec
     *
     * @return array{0: non-empty-string, 1: non-empty-string, 2: non-empty-string} [digestHex, base64-encoded signature, DER-encoded certificate]
     */
    private function parseHashedRekordV002Spec(array $spec): array
    {
        Assert::isArray($spec['hashedRekordV002']);
        $v002Spec = $spec['hashedRekordV002'];

        Assert::isArray($v002Spec['data']);
        Assert::stringNotEmpty($v002Spec['data']['digest']);
        $digest = base64_decode($v002Spec['data']['digest']);
        Assert::stringNotEmpty($digest);

        Assert::isArray($v002Spec['signature']);
        Assert::stringNotEmpty($v002Spec['signature']['content']);

        Assert::isArray($v002Spec['signature']['verifier']);
        Assert::isArray($v002Spec['signature']['verifier']['x509Certificate']);
        Assert::stringNotEmpty($v002Spec['signature']['verifier']['x509Certificate']['rawBytes']);
        $certificateDer = base64_decode($v002Spec['signature']['verifier']['x509Certificate']['rawBytes']);
        Assert::stringNotEmpty($certificateDer);

        return [
            bin2hex($digest),
            $v002Spec['signature']['content'],
            $certificateDer,
        ];
    }

    private function assertDsseEntryMatchesBundleContent(
        int $bundleIndex,
        TransparencyLogEntry $transparencyLogEntry,
        DsseEnvelope $content,
        PemCertificate $certificate
    ): void {
        /** @var array<array-key, mixed> $body */
        $body = json_decode($transparencyLogEntry->canonicalizedBody(), true);
        Assert::isArray($body['spec']);
        Assert::isArray($body['spec']['payloadHash']);
        Assert::stringNotEmpty($body['spec']['payloadHash']['value']);

        $actualPayloadHash = hash('sha256', $content->payload());
        if (! hash_equals($actualPayloadHash, $body['spec']['payloadHash']['value'])) {
            throw DigestMismatch::fromChecksumMismatch($actualPayloadHash, $body['spec']['payloadHash']['value']);
        }

        Assert::isArray($body['spec']['signatures']);
        Assert::isArray($body['spec']['signatures'][0]);
        Assert::stringNotEmpty($body['spec']['signatures'][0]['signature']);
        $entrySignature = base64_decode($body['spec']['signatures'][0]['signature']);
        Assert::stringNotEmpty($entrySignature);

        if (! hash_equals($content->signature(), $entrySignature)) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'signature');
        }

        Assert::stringNotEmpty($body['spec']['signatures'][0]['verifier']);
        $entryCertificatePem = base64_decode($body['spec']['signatures'][0]['verifier']);
        Assert::stringNotEmpty($entryCertificatePem);

        if (! hash_equals($certificate->derEncodedBytes(), Der::bytesFromPem($entryCertificatePem))) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'certificate');
        }
    }

    private function assertIntotoEntryMatchesBundleContent(
        int $bundleIndex,
        TransparencyLogEntry $transparencyLogEntry,
        DsseEnvelope $content,
        PemCertificate $certificate
    ): void {
        /** @var array<array-key, mixed> $body */
        $body = json_decode($transparencyLogEntry->canonicalizedBody(), true);
        Assert::isArray($body['spec']);
        Assert::isArray($body['spec']['content']);
        Assert::isArray($body['spec']['content']['payloadHash']);
        Assert::stringNotEmpty($body['spec']['content']['payloadHash']['value']);

        $actualPayloadHash = hash('sha256', $content->payload());
        if (! hash_equals($actualPayloadHash, $body['spec']['content']['payloadHash']['value'])) {
            throw DigestMismatch::fromChecksumMismatch($actualPayloadHash, $body['spec']['content']['payloadHash']['value']);
        }

        Assert::isArray($body['spec']['content']['envelope']);
        Assert::isArray($body['spec']['content']['envelope']['signatures']);
        Assert::isArray($body['spec']['content']['envelope']['signatures'][0]);
        Assert::stringNotEmpty($body['spec']['content']['envelope']['signatures'][0]['sig']);
        $entrySignatureBase64 = base64_decode($body['spec']['content']['envelope']['signatures'][0]['sig']);
        Assert::stringNotEmpty($entrySignatureBase64);
        $entrySignature = base64_decode($entrySignatureBase64);
        Assert::stringNotEmpty($entrySignature);

        if (! hash_equals($content->signature(), $entrySignature)) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'signature');
        }

        Assert::stringNotEmpty($body['spec']['content']['envelope']['signatures'][0]['publicKey']);
        $entryCertificatePem = base64_decode($body['spec']['content']['envelope']['signatures'][0]['publicKey']);
        Assert::stringNotEmpty($entryCertificatePem);

        if (! hash_equals($certificate->derEncodedBytes(), Der::bytesFromPem($entryCertificatePem))) {
            throw TransparencyLogEntryContentMismatch::forIndex($bundleIndex, 'certificate');
        }
    }

    /**
     * @param TransparencyLogKey $transparencyLogKey
     * @param non-empty-string   $signedContent
     * @param non-empty-string   $signature
     */
    private function verifyTransparencyLogSignature(array $transparencyLogKey, string $signedContent, string $signature): bool
    {
        if ($transparencyLogKey['keyDetails'] === TrustedRoot::KEY_DETAILS_ED25519) {
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

    /** @return array{noteText: non-empty-string, keyHint: non-empty-string, signature: non-empty-string, rootHash: non-empty-string} */
    private function parseCheckpointEnvelope(int $bundleIndex, string $envelope): array
    {
        $lines          = explode("\n", $envelope);
        $blankLineIndex = array_search('', $lines, true);

        if (
            $blankLineIndex === false
            || ! isset($lines[$blankLineIndex + 1])
            || $lines[$blankLineIndex + 1] === ''
            || ! isset($lines[2])
            || $lines[2] === ''
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

        $rootHash = base64_decode($lines[2]);
        if ($rootHash === '') {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        return [
            'noteText' => $noteText,
            'keyHint' => substr($signatureBlob, 0, 4),
            'signature' => $signature,
            'rootHash' => $rootHash,
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

        $caCertificate = $this->trustedRoot->resolveCertificateAuthorityCertificate($attestationCertificateInfo['issuer']);
        if ($caCertificate === null) {
            /** @psalm-suppress MixedArgument */
            throw NoIssuerCertificateInTrustedRoot::fromIssuer($attestationCertificateInfo['issuer']);
        }

        if (openssl_x509_verify($bundle->certificate()->decoratedCertificate(), $caCertificate->decoratedCertificate()) !== 1) {
            /** @psalm-suppress MixedArgument */
            throw IssuerCertificateVerificationFailed::fromIssuer($attestationCertificateInfo['issuer']);
        }
    }

    private function assertCertificateHasATrustedSignedCertificateTimestamp(Bundle $bundle): void
    {
        $logIds = $this->extractSignedCertificateTimestampLogIds($bundle->certificate()->derEncodedBytes());

        foreach ($logIds as $logId) {
            if ($this->trustedRoot->isCertificateTransparencyLogIdTrusted($logId)) {
                return;
            }
        }

        throw UntrustedCertificateTransparencyLogKey::new();
    }

    /** @return non-empty-list<non-empty-string> */
    private function extractSignedCertificateTimestampLogIds(string $certificateDer): array
    {
        [$certTag, $certContent] = Der::readTlv($certificateDer, 0);
        Assert::same($certTag, Der::TAG_SEQUENCE);

        [$tbsTag, $tbsContent] = Der::readTlv($certContent, 0);
        Assert::same($tbsTag, Der::TAG_SEQUENCE);

        $extensionsBlock = null;
        $offset          = 0;
        while ($offset < strlen($tbsContent)) {
            [$fieldTag, $fieldValue, $offset] = Der::readTlv($tbsContent, $offset);
            if ($fieldTag !== Der::TAG_CONTEXT_EXTENSIONS) {
                continue;
            }

            $extensionsBlock = $fieldValue;
        }

        Assert::stringNotEmpty($extensionsBlock);

        [$extSeqTag, $extSeqContent] = Der::readTlv($extensionsBlock, 0);
        Assert::same($extSeqTag, Der::TAG_SEQUENCE);

        $sctExtensionValue = null;
        $offset            = 0;
        while ($offset < strlen($extSeqContent)) {
            [$extTag, $extContent, $offset] = Der::readTlv($extSeqContent, $offset);
            if ($extTag !== Der::TAG_SEQUENCE) {
                continue;
            }

            [$oidTag, $oidValue, $innerOffset] = Der::readTlv($extContent, 0);
            Assert::same($oidTag, Der::TAG_OBJECT_IDENTIFIER);
            if ($oidValue !== self::CT_PRECERT_SCTS_EXTENSION_OID_DER) {
                continue;
            }

            [$nextTag, $nextValue, $innerOffset] = Der::readTlv($extContent, $innerOffset);
            if ($nextTag === Der::TAG_BOOLEAN) {
                [$nextTag, $nextValue] = Der::readTlv($extContent, $innerOffset);
            }

            Assert::same($nextTag, Der::TAG_OCTET_STRING);
            $sctExtensionValue = $nextValue;
        }

        Assert::stringNotEmpty($sctExtensionValue);

        [$innerOctetStringTag, $sctList] = Der::readTlv($sctExtensionValue, 0);
        Assert::same($innerOctetStringTag, Der::TAG_OCTET_STRING);
        Assert::true(strlen($sctList) >= 2);

        $logIds = [];
        $offset = 2; // Skip the 2-byte total-length prefix of the SignedCertificateTimestampList.
        while ($offset < strlen($sctList)) {
            Assert::true($offset + 2 <= strlen($sctList));
            $sctLength = (ord($sctList[$offset]) << 8) | ord($sctList[$offset + 1]);
            $offset   += 2;

            Assert::true($offset + $sctLength <= strlen($sctList));
            $sct     = substr($sctList, $offset, $sctLength);
            $offset += $sctLength;

            // SignedCertificateTimestamp ::= version(1) || log_id(32) || timestamp(8) || extensions(...) || signature(...)
            Assert::true(strlen($sct) >= 33);
            $logId = substr($sct, 1, 32);
            Assert::stringNotEmpty($logId);
            $logIds[] = $logId;
        }

        Assert::isNonEmptyList($logIds);

        return $logIds;
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

    private function assertDigestFromAttestationMatchesActual(FilenameWithChecksum $file, DsseEnvelope $envelope): void
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

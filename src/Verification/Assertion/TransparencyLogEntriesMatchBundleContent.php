<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\TransparencyLogEntry;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogEntryContentMismatch;
use Webmozart\Assert\Assert;

use function base64_decode;
use function bin2hex;
use function hash;
use function hash_equals;
use function json_decode;

final class TransparencyLogEntriesMatchBundleContent implements VerifyBundleCheck
{
    private const HASHEDREKORD_VERSION_0_0_2 = '0.0.2';

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
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
}

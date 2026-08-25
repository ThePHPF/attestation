<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedDigestAlgorithm;
use Webmozart\Assert\Assert;

use function base64_decode;
use function bin2hex;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class MessageSignature implements SigstoreBundleContent
{
    /** @link https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto */
    private const SUPPORTED_DIGEST_ALGORITHM = 'SHA2_256';

    /** @var non-empty-string */
    public string $digestHex;
    /** @var non-empty-string */
    public string $signature;

    /**
     * @param non-empty-string $digestHex
     * @param non-empty-string $signature
     */
    private function __construct(string $digestHex, string $signature)
    {
        $this->digestHex = $digestHex;
        $this->signature = $signature;
    }

    /** @param array<array-key, mixed> $messageSignature */
    public static function fromBundleMessageSignature(array $messageSignature): self
    {
        Assert::keyExists($messageSignature, 'messageDigest');
        Assert::isArray($messageSignature['messageDigest']);
        Assert::keyExists($messageSignature['messageDigest'], 'algorithm');
        Assert::stringNotEmpty($messageSignature['messageDigest']['algorithm']);
        Assert::keyExists($messageSignature['messageDigest'], 'digest');
        Assert::stringNotEmpty($messageSignature['messageDigest']['digest']);

        if ($messageSignature['messageDigest']['algorithm'] !== self::SUPPORTED_DIGEST_ALGORITHM) {
            throw UnsupportedDigestAlgorithm::fromAlgorithm($messageSignature['messageDigest']['algorithm']);
        }

        Assert::keyExists($messageSignature, 'signature');
        Assert::stringNotEmpty($messageSignature['signature']);

        $decodedDigest = base64_decode($messageSignature['messageDigest']['digest']);
        Assert::stringNotEmpty($decodedDigest);

        $decodedSignature = base64_decode($messageSignature['signature']);
        Assert::stringNotEmpty($decodedSignature);

        return new self(bin2hex($decodedDigest), $decodedSignature);
    }
}

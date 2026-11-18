<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use Composer\Factory;
use Composer\IO\NullIO;
use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;
use ThePhpFoundation\Attestation\BundleSource\Exception\BundleResponseTooLarge;
use ThePhpFoundation\Attestation\BundleSource\Exception\FailedToDecompressBundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\FailedToFetchBundleUrl;
use ThePhpFoundation\Attestation\BundleSource\Exception\UntrustedBundleUrl;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function array_map;
use function is_array;
use function is_string;
use function json_decode;
use function ord;
use function snappy_uncompress;
use function str_starts_with;
use function strlen;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class GitHubApi
{
    private const DEFAULT_BASE_URL                      = 'https://api.github.com';
    private const MAX_COMPRESSED_BUNDLE_SIZE            = 8 * 1024 * 1024;
    private const MAX_DECLARED_UNCOMPRESSED_BUNDLE_SIZE = 8 * 1024 * 1024;

    /**
     * Pinning to specific GH API version so we can control BC surface
     * https://docs.github.com/en/rest/about-the-rest-api/api-versions
     *
     * @link https://github.com/ThePHPF/attestation/issues/31
     *
     * @todo update to 2026-03-10
     */
    private const API_VERSION = '2022-11-28';

    /** @param non-empty-string $baseUrl */
    public function __construct(private string $baseUrl, private HttpDownloader $httpDownloader)
    {
    }

    public static function factory(): self
    {
        $io     = new NullIO();
        $config = Factory::createConfig();
        $io->loadConfiguration($config);

        return new self(self::DEFAULT_BASE_URL, Factory::createHttpDownloader($io, $config));
    }

    /**
     * @param non-empty-string $path
     *
     * @throws TransportException
     */
    public function getJson(string $path): mixed
    {
        return $this->httpDownloader->get(
            $this->baseUrl . $path,
            [
                'retry-auth-failure' => true,
                'http' => [
                    'method' => 'GET',
                    'header' => ['X-GitHub-Api-Version: ' . self::API_VERSION],
                ],
            ],
        )->decodeJson();
    }

    /**
     * @param non-empty-string $url
     *
     * @throws TransportException
     */
    public function getUrl(string $url): Response
    {
        return $this->httpDownloader->get(
            $url,
            [
                'retry-auth-failure' => false,
                'http' => [
                    'method' => 'GET',
                    'header' => [],
                ],
            ],
        );
    }

    /**
     * @param non-empty-string $path
     *
     * @return list<array{initiator: string|null, bundle: array<array-key, mixed>}>
     *
     * @throws TransportException
     */
    public function attestations(string $path): array
    {
        $decodedJson = $this->getJson($path);

        Assert::isArray($decodedJson);
        Assert::keyExists($decodedJson, 'attestations');
        Assert::isList($decodedJson['attestations']);

        return array_map(
            /** @param mixed $attestation */
            function ($attestation): array {
                Assert::isArray($attestation);

                return [
                    'initiator' => array_key_exists('initiator', $attestation) && is_string($attestation['initiator']) ? $attestation['initiator'] : null,
                    'bundle' => $this->pullBundleFromUrlOrInline($attestation),
                ];
            },
            $decodedJson['attestations'],
        );
    }

    /**
     * GitHub may return `bundle` inline (old behaviour), or may give us a
     * `bundle_url`. The `bundle_url` is a short-lived token URL to grab the
     * bundle from; however the bundle is compressed using Snappy (a Google
     * compression algo), but we can use `flow-php/snappy` to decompress and
     * return the final bundle.
     *
     * @param array<array-key, mixed> $attestation
     *
     * @return array<array-key, mixed>
     */
    private function pullBundleFromUrlOrInline(array $attestation): array
    {
        if (array_key_exists('bundle', $attestation) && is_array($attestation['bundle'])) {
            return $attestation['bundle'];
        }

        Assert::keyExists($attestation, 'bundle_url');
        Assert::stringNotEmpty($attestation['bundle_url']);
        $bundleUrl = $attestation['bundle_url'];

        if (! str_starts_with($bundleUrl, 'https://')) {
            throw UntrustedBundleUrl::fromUrl($bundleUrl);
        }

        try {
            $response = $this->getUrl($bundleUrl);
        } catch (TransportException $transportException) {
            throw FailedToFetchBundleUrl::fromUrl($bundleUrl, $transportException->getStatusCode());
        }

        $compressedBundle = $response->getBody();
        if ($compressedBundle === null || $compressedBundle === '') {
            throw FailedToFetchBundleUrl::fromUrl($bundleUrl, $response->getStatusCode());
        }

        if (strlen($compressedBundle) > self::MAX_COMPRESSED_BUNDLE_SIZE) {
            throw BundleResponseTooLarge::fromUrl($bundleUrl, strlen($compressedBundle), self::MAX_COMPRESSED_BUNDLE_SIZE);
        }

        $declaredUncompressedLength = self::declaredSnappyUncompressedLength($compressedBundle);
        if ($declaredUncompressedLength !== null && $declaredUncompressedLength > self::MAX_DECLARED_UNCOMPRESSED_BUNDLE_SIZE) {
            throw BundleResponseTooLarge::fromUrl($bundleUrl, $declaredUncompressedLength, self::MAX_DECLARED_UNCOMPRESSED_BUNDLE_SIZE);
        }

        $decompressedBundle = snappy_uncompress($compressedBundle);
        if ($decompressedBundle === false) {
            throw FailedToDecompressBundle::fromUrl($bundleUrl);
        }

        /** @var mixed $decodedBundle */
        $decodedBundle = json_decode($decompressedBundle, true);
        Assert::isArray($decodedBundle);

        return $decodedBundle;
    }

    private static function declaredSnappyUncompressedLength(string $compressed): int|null
    {
        $result = 0;
        $shift  = 0;
        $length = strlen($compressed);

        for ($offset = 0; $shift < 32 && $offset < $length; $offset++) {
            $byte = ord($compressed[$offset]);
            $val  = $byte & 0x7F;

            if ((($val << $shift) >> $shift) !== $val) {
                return null;
            }

            $result |= $val << $shift;

            if ($byte < 128) {
                return $result;
            }

            $shift += 7;
        }

        return null;
    }
}

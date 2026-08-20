<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use Composer\Factory;
use Composer\IO\NullIO;
use Composer\Util\HttpDownloader;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\FailedToFetchBundleUrl;
use ThePhpFoundation\Attestation\Verification\Exception\MissingAttestation;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function array_map;
use function is_array;
use function json_decode;
use function snappy_uncompress;
use function sprintf;

class DownloadGitHubBundle implements BundleSource
{
    private const GITHUB_API_URL = 'https://api.github.com';

    /**
     * Pinning to specific GH API version so we can control BC surface
     * https://docs.github.com/en/rest/about-the-rest-api/api-versions
     *
     * @link https://github.com/ThePHPF/attestation/issues/31
     *
     * @todo update to 2026-03-10
     */
    private const GITHUB_API_VERSION = '2022-11-28';

    /** @var non-empty-string */
    private string $owner;
    /** @var non-empty-string */
    private string $githubApiBaseUrl;
    private HttpDownloader $httpDownloader;

    /**
     * @param non-empty-string $owner
     * @param non-empty-string $githubApiBaseUrl
     */
    public function __construct(string $owner, string $githubApiBaseUrl, HttpDownloader $httpDownloader)
    {
        $this->owner            = $owner;
        $this->githubApiBaseUrl = $githubApiBaseUrl;
        $this->httpDownloader   = $httpDownloader;
    }

    /** @param non-empty-string $owner */
    public static function factory(string $owner): self
    {
        $io     = new NullIO();
        $config = Factory::createConfig();
        $io->loadConfiguration($config);
        $http = Factory::createHttpDownloader($io, $config);

        return new self($owner, self::GITHUB_API_URL, $http);
    }

    /** @inheritDoc */
    public function getBundles(FilenameWithChecksum $file): array
    {
        $attestationUrl = sprintf(
            '%s/orgs/%s/attestations/sha256:%s?predicate_type=provenance',
            $this->githubApiBaseUrl,
            $this->owner,
            $file->checksum(),
        );

        try {
            $decodedJson = $this->httpDownloader->get(
                $attestationUrl,
                [
                    'retry-auth-failure' => true,
                    'http' => [
                        'method' => 'GET',
                        'header' => ['X-GitHub-Api-Version: ' . self::GITHUB_API_VERSION],
                    ],
                ],
            )->decodeJson();

            Assert::isArray($decodedJson);
            Assert::keyExists($decodedJson, 'attestations');
            Assert::isList($decodedJson['attestations']);

            if ($decodedJson['attestations'] === []) {
                throw MissingAttestation::from($file);
            }

            return array_map(
                /** @param mixed $attestation */
                function ($attestation): Bundle {
                    Assert::isArray($attestation);

                    return Bundle::fromBundleWithDsseEnvelope(
                        $this->pullBundleFromUrlOrInline($attestation),
                    );
                },
                $decodedJson['attestations'],
            );
        } catch (TransportException $transportException) {
            if ($transportException->getStatusCode() === 404) {
                throw MissingAttestation::from($file);
            }

            throw $transportException;
        }
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

        try {
            $response = $this->httpDownloader->get(
                $bundleUrl,
                [
                    'retry-auth-failure' => false,
                    'http' => [
                        'method' => 'GET',
                        'header' => [],
                    ],
                ],
            );
        } catch (TransportException $transportException) {
            throw FailedToFetchBundleUrl::fromUrl($bundleUrl, $transportException->getStatusCode());
        }

        $compressedBundle = $response->getBody();
        if ($compressedBundle === null || $compressedBundle === '') {
            throw FailedToFetchBundleUrl::fromUrl($bundleUrl, $response->getStatusCode());
        }

        $decompressedBundle = snappy_uncompress($compressedBundle);

        /** @var mixed $decodedBundle */
        $decodedBundle = json_decode($decompressedBundle, true);
        Assert::isArray($decodedBundle);

        return $decodedBundle;
    }
}

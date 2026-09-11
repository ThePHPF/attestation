<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\BundleSource;

use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubBundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\BundleResponseTooLarge;
use ThePhpFoundation\Attestation\BundleSource\Exception\FailedToDecompressBundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use Webmozart\Assert\Assert;

use function json_encode;
use function str_contains;
use function str_repeat;

/** @covers \ThePhpFoundation\Attestation\BundleSource\DownloadGitHubBundle */
final class DownloadGitHubBundleTest extends TestCase
{
    private const BUNDLE_URL = 'https://example.test/bundle';

    private function downloaderReturning(string $bundleResponseBody): DownloadGitHubBundle
    {
        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->method('get')->willReturnCallback(
            static function (string $url) use ($bundleResponseBody): Response {
                Assert::stringNotEmpty($url);

                if (str_contains($url, '/attestations/')) {
                    return new Response(['url' => $url], 200, [], (string) json_encode([
                        'attestations' => [['bundle_url' => self::BUNDLE_URL]],
                    ]));
                }

                return new Response(['url' => $url], 200, [], $bundleResponseBody);
            },
        );

        return new DownloadGitHubBundle('owner', 'https://api.example.test', $httpDownloader);
    }

    public function testThrowsWhenTheCompressedBundleResponseExceedsTheSizeCap(): void
    {
        $downloader = $this->downloaderReturning(str_repeat('a', 8 * 1024 * 1024 + 1));

        $this->expectException(BundleResponseTooLarge::class);
        $downloader->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }

    public function testThrowsWhenTheCompressedBundleResponseFailsToDecompress(): void
    {
        $downloader = $this->downloaderReturning("\xFF\xFF\xFF\xFF");

        $this->expectException(FailedToDecompressBundle::class);
        $downloader->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }

    public function testThrowsWhenTheDeclaredUncompressedLengthExceedsTheCapWithoutAttemptingToDecompress(): void
    {
        $downloader = $this->downloaderReturning("\x80\x80\x80\x60\x00");

        $this->expectException(BundleResponseTooLarge::class);
        $downloader->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }
}

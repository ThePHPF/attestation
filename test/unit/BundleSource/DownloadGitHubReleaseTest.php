<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubRelease;
use ThePhpFoundation\Attestation\BundleSource\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\BundleSource\GitHubApi;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\GitHubReleaseTag;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;
use function json_encode;

/** @covers \ThePhpFoundation\Attestation\BundleSource\DownloadGitHubRelease */
final class DownloadGitHubReleaseTest extends TestCase
{
    private const RELEASE_BUNDLE_FIXTURE = __DIR__ . '/../../fixture/pie-1.5.5-release-bundle.json';
    private const RELEASE_TAG_SHA        = 'a41ca99acf93460f75a2acd830b2b8f013571e3a';
    private const PIE_PHAR_DIGEST        = '2ca0dff6868f1b53c095625674deef38ac698588e0a25e4321cd834a5b7553bc';

    /** @return array<array-key, mixed> */
    private static function releaseBundle(): array
    {
        $contents = file_get_contents(self::RELEASE_BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return $decoded;
    }

    /**
     * @param non-empty-string $tagName
     * @param list<string>     $initiators
     */
    private function downloader(string $tagName, array $initiators): DownloadGitHubRelease
    {
        $attestations = [];
        foreach ($initiators as $initiator) {
            $attestations[] = ['initiator' => $initiator, 'bundle' => self::releaseBundle()];
        }

        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->expects(self::once())
            ->method('get')
            ->with('https://api.example.test/repos/php/pie/attestations/sha1:' . self::RELEASE_TAG_SHA . '?predicate_type=release')
            ->willReturn(new Response(['url' => 'irrelevant'], 200, [], (string) json_encode(['attestations' => $attestations])));

        return new DownloadGitHubRelease(
            'php',
            'pie',
            GitHubReleaseTag::from($tagName, self::RELEASE_TAG_SHA),
            new GitHubApi('https://api.example.test', $httpDownloader),
        );
    }

    public function testReturnsGitHubInitiatedAttestationsForTheTagAndFile(): void
    {
        $bundles = $this->downloader('1.5.5', ['github', 'user'])
            ->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('pie.phar', self::PIE_PHAR_DIGEST));

        self::assertCount(1, $bundles);
    }

    public function testThrowsWhenNoAttestationIsForTheTag(): void
    {
        $this->expectException(MissingAttestation::class);
        $this->downloader('1.5.4', ['github'])
            ->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('pie.phar', self::PIE_PHAR_DIGEST));
    }

    public function testThrowsWhenNoAttestationHasTheFileAsASubject(): void
    {
        $this->expectException(MissingAttestation::class);
        $this->downloader('1.5.5', ['github'])
            ->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('pie.phar', 'not-the-pie-phar-digest'));
    }

    public function testThrowsWhenTheApiReturnsNotFound(): void
    {
        $notFound = new TransportException('Not Found', 404);
        $notFound->setStatusCode(404);

        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->method('get')->willThrowException($notFound);

        $this->expectException(MissingAttestation::class);
        (new DownloadGitHubRelease(
            'php',
            'pie',
            GitHubReleaseTag::from('1.5.5', self::RELEASE_TAG_SHA),
            new GitHubApi('https://api.example.test', $httpDownloader),
        ))->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('pie.phar', self::PIE_PHAR_DIGEST));
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\Exception\ReleaseTagNotFound;
use ThePhpFoundation\Attestation\BundleSource\GitHubApi;
use ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag;

use function json_encode;

/** @covers \ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag */
final class ResolveGitHubReleaseTagTest extends TestCase
{
    public function testResolvesATagNameToTheShaItsRefPointsTo(): void
    {
        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->expects(self::once())
            ->method('get')
            ->with('https://api.example.test/repos/php/pie/git/ref/tags/1.5.5')
            ->willReturn(new Response(['url' => 'irrelevant'], 200, [], (string) json_encode([
                'ref' => 'refs/tags/1.5.5',
                'object' => ['type' => 'tag', 'sha' => 'a41ca99acf93460f75a2acd830b2b8f013571e3a'],
            ])));

        $tag = (new ResolveGitHubReleaseTag(new GitHubApi('https://api.example.test', $httpDownloader)))->resolve('php', 'pie', '1.5.5');

        self::assertSame('1.5.5', $tag->tagName());
        self::assertSame('a41ca99acf93460f75a2acd830b2b8f013571e3a', $tag->sha());
    }

    public function testThrowsWhenTheTagDoesNotExist(): void
    {
        $notFound = new TransportException('Not Found', 404);
        $notFound->setStatusCode(404);

        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->method('get')->willThrowException($notFound);

        $this->expectException(ReleaseTagNotFound::class);
        (new ResolveGitHubReleaseTag(new GitHubApi('https://api.example.test', $httpDownloader)))->resolve('php', 'pie', '0.0.0-does-not-exist');
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\BundleSource;

use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\GitHubApi;

use function json_encode;

/** @covers \ThePhpFoundation\Attestation\BundleSource\GitHubApi */
final class GitHubApiTest extends TestCase
{
    public function testGetJsonRequestsThePathWithThePinnedApiVersionAndDecodesTheResponse(): void
    {
        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->expects(self::once())
            ->method('get')
            ->with(
                'https://api.example.test/some/path',
                [
                    'retry-auth-failure' => true,
                    'http' => [
                        'method' => 'GET',
                        'header' => ['X-GitHub-Api-Version: 2022-11-28'],
                    ],
                ],
            )
            ->willReturn(new Response(['url' => 'irrelevant'], 200, [], (string) json_encode(['some' => 'json'])));

        self::assertSame(
            ['some' => 'json'],
            (new GitHubApi('https://api.example.test', $httpDownloader))->getJson('/some/path'),
        );
    }

    public function testGetUrlRequestsTheUrlAsGivenWithoutApiHeadersOrAuthRetry(): void
    {
        $response = new Response(['url' => 'irrelevant'], 200, [], 'raw body');

        $httpDownloader = $this->createMock(HttpDownloader::class);
        $httpDownloader->expects(self::once())
            ->method('get')
            ->with(
                'https://elsewhere.example.test/bundle',
                [
                    'retry-auth-failure' => false,
                    'http' => [
                        'method' => 'GET',
                        'header' => [],
                    ],
                ],
            )
            ->willReturn($response);

        self::assertSame(
            $response,
            (new GitHubApi('https://api.example.test', $httpDownloader))->getUrl('https://elsewhere.example.test/bundle'),
        );
    }
}

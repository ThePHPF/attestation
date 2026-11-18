<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\BundleSource;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag;

/** @covers \ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag */
final class ResolveGitHubReleaseTagTest extends TestCase
{
    public function testResolvesAKnownReleaseTag(): void
    {
        $tag = ResolveGitHubReleaseTag::factory()->resolve('php', 'pie', '1.5.5');

        self::assertSame('a41ca99acf93460f75a2acd830b2b8f013571e3a', $tag->sha());
    }
}

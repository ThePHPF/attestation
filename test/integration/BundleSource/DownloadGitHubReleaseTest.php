<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\BundleSource;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubRelease;
use ThePhpFoundation\Attestation\BundleSource\ResolveGitHubReleaseTag;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;

/** @covers \ThePhpFoundation\Attestation\BundleSource\DownloadGitHubRelease */
final class DownloadGitHubReleaseTest extends TestCase
{
    public function testDownloadsAndVerifiesTheReleaseAttestationForAKnownReleaseAsset(): void
    {
        $file = FilenameWithChecksum::fromFilenameAndChecksum('pie.phar', '2ca0dff6868f1b53c095625674deef38ac698588e0a25e4321cd834a5b7553bc');
        $tag  = ResolveGitHubReleaseTag::factory()->resolve('php', 'pie', '1.5.5');

        $bundles = DownloadGitHubRelease::factory('php', 'pie', $tag)->getBundles($file);

        $this->expectNotToPerformAssertions();
        VerifyBundleWithOpenSsl::forGitHubRelease($tag)->verify($bundles, $file);
    }
}

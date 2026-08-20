<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\BundleSource;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubBundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\MissingAttestation;

/** @covers \ThePhpFoundation\Attestation\BundleSource\DownloadGitHubBundle */
class DownloadGitHubBundleTest extends TestCase
{
    private const GENUINE_PIE_PHAR = __DIR__ . '/../../fixture/genuine-pie.phar';

    public function testDownloadsBundlesForAKnownAttestedArtifact(): void
    {
        $bundles = DownloadGitHubBundle::factory('php')->getBundles(
            FilenameWithChecksum::fromFilename(self::GENUINE_PIE_PHAR),
        );

        foreach ($bundles as $bundle) {
            self::assertInstanceOf(Bundle::class, $bundle);
        }
    }

    public function testThrowsWhenNoAttestationIsFound(): void
    {
        $this->expectException(MissingAttestation::class);
        DownloadGitHubBundle::factory('php')->getBundles(
            FilenameWithChecksum::fromFilename(__FILE__),
        );
    }
}

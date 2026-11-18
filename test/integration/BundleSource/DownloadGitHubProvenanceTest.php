<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\BundleSource;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\DownloadGitHubProvenance;
use ThePhpFoundation\Attestation\BundleSource\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\FilenameWithChecksum;

/** @covers \ThePhpFoundation\Attestation\BundleSource\DownloadGitHubProvenance */
class DownloadGitHubProvenanceTest extends TestCase
{
    private const PIE_PHAR = __DIR__ . '/../../fixture/pie.phar';

    public function testDownloadsBundlesForAKnownAttestedArtifact(): void
    {
        $bundles = DownloadGitHubProvenance::factory('php')->getBundles(
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
        );

        foreach ($bundles as $bundle) {
            self::assertInstanceOf(Bundle::class, $bundle);
        }
    }

    public function testThrowsWhenNoAttestationIsFound(): void
    {
        $this->expectException(MissingAttestation::class);
        DownloadGitHubProvenance::factory('php')->getBundles(
            FilenameWithChecksum::fromFilename(__FILE__),
        );
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\BundleSource;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\FailedToReadBundleFile;
use ThePhpFoundation\Attestation\BundleSource\OnDiskBundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use Webmozart\Assert\Assert;

use function file_put_contents;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/** @covers \ThePhpFoundation\Attestation\BundleSource\OnDiskBundle */
final class OnDiskBundleTest extends TestCase
{
    private const BUNDLE_FIXTURE = __DIR__ . '/../../fixture/bundle.json';

    /** @var list<string> */
    private array $tempFiles = [];

    public function tearDown(): void
    {
        foreach ($this->tempFiles as $tempFile) {
            unlink($tempFile);
        }

        $this->tempFiles = [];
    }

    /** @return non-empty-string */
    private function createTempFile(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'on-disk-bundle-test-');
        Assert::stringNotEmpty($path);
        file_put_contents($path, $contents);
        $this->tempFiles[] = $path;

        return $path;
    }

    public function testGetBundlesReturnsSingleBundleFromFile(): void
    {
        $source  = new OnDiskBundle(self::BUNDLE_FIXTURE);
        $bundles = $source->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));

        self::assertCount(1, $bundles);
        self::assertInstanceOf(Bundle::class, $bundles[0]);
    }

    public function testGetBundlesThrowsWhenFileDoesNotExist(): void
    {
        $source = new OnDiskBundle(self::BUNDLE_FIXTURE . '.does-not-exist');

        $this->expectException(FailedToReadBundleFile::class);
        $this->expectExceptionMessage('does not exist or is not readable');
        $source->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }

    public function testGetBundlesThrowsWhenFileIsEmpty(): void
    {
        $source = new OnDiskBundle($this->createTempFile(''));

        $this->expectException(FailedToReadBundleFile::class);
        $this->expectExceptionMessage('could not be read, or was empty');
        $source->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }

    public function testGetBundlesThrowsWhenFileIsNotValidJson(): void
    {
        $source = new OnDiskBundle(__FILE__);

        $this->expectException(FailedToReadBundleFile::class);
        $this->expectExceptionMessage('does not contain valid JSON');
        $source->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }

    public function testGetBundlesThrowsWhenJsonIsNotAnObject(): void
    {
        $source = new OnDiskBundle($this->createTempFile('"just a valid JSON string"'));

        $this->expectException(FailedToReadBundleFile::class);
        $this->expectExceptionMessage('does not decode to a JSON object');
        $source->getBundles(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'));
    }
}

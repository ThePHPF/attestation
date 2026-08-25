<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use JsonException;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\FailedToReadBundleFile;
use ThePhpFoundation\Attestation\FilenameWithChecksum;

use function file_get_contents;
use function is_array;
use function is_readable;
use function json_decode;

use const JSON_THROW_ON_ERROR;

class OnDiskBundle implements BundleSource
{
    /** @var non-empty-string */
    private string $bundleFilePath;

    /** @param non-empty-string $bundleFilePath */
    public function __construct(string $bundleFilePath)
    {
        $this->bundleFilePath = $bundleFilePath;
    }

    /** @inheritDoc */
    public function getBundles(FilenameWithChecksum $file): array
    {
        if (! is_readable($this->bundleFilePath)) {
            throw FailedToReadBundleFile::notReadable($this->bundleFilePath);
        }

        $contents = file_get_contents($this->bundleFilePath);
        if ($contents === false || $contents === '') {
            throw FailedToReadBundleFile::noContents($this->bundleFilePath);
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw FailedToReadBundleFile::invalidJson($this->bundleFilePath, $exception);
        }

        if (! is_array($decoded)) {
            throw FailedToReadBundleFile::notAJsonObject($this->bundleFilePath);
        }

        return [Bundle::fromBundle($decoded)];
    }
}

<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource\Exception;

use JsonException;

use function sprintf;

class FailedToReadBundleFile extends BundleSourceException
{
    public static function notReadable(string $bundleFilePath): self
    {
        return new self(sprintf(
            'Bundle file "%s" does not exist or is not readable',
            $bundleFilePath,
        ));
    }

    public static function noContents(string $bundleFilePath): self
    {
        return new self(sprintf(
            'Bundle file "%s" could not be read, or was empty',
            $bundleFilePath,
        ));
    }

    public static function invalidJson(string $bundleFilePath, JsonException $previous): self
    {
        return new self(
            sprintf(
                'Bundle file "%s" does not contain valid JSON: %s',
                $bundleFilePath,
                $previous->getMessage(),
            ),
            0,
            $previous,
        );
    }

    public static function notAJsonObject(string $bundleFilePath): self
    {
        return new self(sprintf(
            'Bundle file "%s" does not decode to a JSON object',
            $bundleFilePath,
        ));
    }
}

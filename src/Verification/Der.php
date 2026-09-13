<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use Webmozart\Assert\Assert;

use function base64_decode;
use function chr;
use function ord;
use function str_replace;
use function strlen;
use function substr;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Der
{
    public const TAG_BOOLEAN            = 0x01;
    public const TAG_INTEGER            = 0x02;
    public const TAG_OCTET_STRING       = 0x04;
    public const TAG_OBJECT_IDENTIFIER  = 0x06;
    public const TAG_GENERALIZED_TIME   = 0x18;
    public const TAG_SEQUENCE           = 0x30;
    public const TAG_CONTEXT_EXTENSIONS = 0xA3;

    private const MAX_LENGTH_BYTES = 4;

    /** @return non-empty-string */
    public static function bytesFromPem(string $pem): string
    {
        $der = base64_decode(str_replace(
            ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"],
            '',
            $pem,
        ));
        Assert::stringNotEmpty($der);

        return $der;
    }

    /** @return non-empty-string */
    public static function bytesFromPublicKeyPem(string $pem): string
    {
        $der = base64_decode(str_replace(
            ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\r", "\n"],
            '',
            $pem,
        ));
        Assert::stringNotEmpty($der);

        return $der;
    }

    public static function writeTlv(int $tag, string $value): string
    {
        return chr($tag & 0xFF) . self::writeLength(strlen($value)) . $value;
    }

    private static function writeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length & 0xFF);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes    = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes) & 0xFF) . $bytes;
    }

    /** @return array{0: int, 1: string, 2: int} */
    public static function readTlv(string $data, int $offset): array
    {
        $startOffset = $offset;

        Assert::true($offset + 2 <= strlen($data));

        $tag = ord($data[$offset]);
        $offset++;

        $lengthByte = ord($data[$offset]);
        $offset++;

        if ($lengthByte < 0x80) {
            $length = $lengthByte;
        } else {
            $numberOfLengthBytes = $lengthByte & 0x7F;
            Assert::lessThanEq($numberOfLengthBytes, self::MAX_LENGTH_BYTES);
            Assert::true($offset + $numberOfLengthBytes <= strlen($data));

            $length = 0;
            for ($i = 0; $i < $numberOfLengthBytes; $i++) {
                $length = ($length << 8) | ord($data[$offset]);
                $offset++;
            }
        }

        Assert::true($offset + $length <= strlen($data));
        $value = substr($data, $offset, $length);

        $nextOffset = $offset + $length;
        Assert::greaterThan($nextOffset, $startOffset);

        return [$tag, $value, $nextOffset];
    }
}

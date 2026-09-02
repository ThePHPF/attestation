<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use Webmozart\Assert\Assert;

use function array_key_exists;
use function bcadd;
use function bccomp;
use function bcdiv;
use function bcmod;
use function bcmul;
use function bcpowmod;
use function bcsub;
use function bin2hex;
use function hexdec;
use function ltrim;
use function str_split;
use function strlen;
use function strrev;

/**
 * Verifies an ECDSA signature against an already-computed digest (rather than the signed message itself),
 * which ext-openssl has no way to do: openssl_verify() always hashes the message it's given internally.
 *
 * Requires ext-bcmath; callers must check extension_loaded('bcmath') first.
 *
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @link https://github.com/sigstore/sigstore-js/blob/main/packages/conformance/src/commands/verify-bundle.ts
 *       sigstore-js hits the exact same ext-openssl/Node crypto gap and works around it with the `elliptic`
 *       npm package; this does the equivalent raw point arithmetic using ext-bcmath instead of a dependency.
 */
final class RawEcdsaDigestVerifier
{
    private const CURVES = [
        'prime256v1' => [
            'p' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
            'a' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
            'gx' => '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
            'gy' => '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
            'n' => 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
        ],
        'secp384r1' => [
            'p' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
            'a' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
            'gx' => 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
            'gy' => '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
            'n' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
        ],
    ];

    public static function isCurveSupported(string $curveName): bool
    {
        return array_key_exists($curveName, self::CURVES);
    }

    /**
     * @param non-empty-string $curveName    an OpenSSL EC curve name, e.g. 'prime256v1' or 'secp384r1'
     * @param non-empty-string $digest       raw digest bytes
     * @param non-empty-string $signatureDer ASN.1 DER SEQUENCE{INTEGER r, INTEGER s}
     * @param non-empty-string $qxBytes      public key X coordinate, raw bytes
     * @param non-empty-string $qyBytes      public key Y coordinate, raw bytes
     */
    public static function verify(string $curveName, string $digest, string $signatureDer, string $qxBytes, string $qyBytes): bool
    {
        Assert::keyExists(self::CURVES, $curveName);
        $curve = self::CURVES[$curveName];

        $p = self::hex2dec($curve['p']);
        $a = self::hex2dec($curve['a']);
        $n = self::hex2dec($curve['n']);

        [$rHex, $sHex] = self::parseSignature($signatureDer);

        $r = self::hex2dec($rHex);
        $s = self::hex2dec($sHex);

        if (bccomp($r, '1') < 0 || bccomp($r, bcsub($n, '1')) > 0) {
            return false;
        }

        if (bccomp($s, '1') < 0 || bccomp($s, bcsub($n, '1')) > 0) {
            return false;
        }

        $e = self::hex2dec(bin2hex($digest));

        $w  = self::modinv($s, $n);
        $u1 = bcmod(bcmul($e, $w), $n);
        $u2 = bcmod(bcmul($r, $w), $n);

        $basePoint   = [self::hex2dec($curve['gx']), self::hex2dec($curve['gy'])];
        $publicKey   = [self::hex2dec(bin2hex($qxBytes)), self::hex2dec(bin2hex($qyBytes))];
        $u1BasePoint = self::pointMultiply($basePoint, $u1, $p, $a);
        $u2PublicKey = self::pointMultiply($publicKey, $u2, $p, $a);

        $sum = self::pointAdd($u1BasePoint, $u2PublicKey, $p, $a);
        if ($sum === null) {
            return false;
        }

        [$x1] = $sum;

        return bccomp(bcmod($x1, $n), $r) === 0;
    }

    /** @return array{0: non-empty-string, 1: non-empty-string} [r as hex, s as hex] */
    private static function parseSignature(string $signatureDer): array
    {
        [$sequenceTag, $sequenceContent] = Der::readTlv($signatureDer, 0);
        Assert::same($sequenceTag, Der::TAG_SEQUENCE);

        [$rTag, $rValue, $offsetAfterR] = Der::readTlv($sequenceContent, 0);
        Assert::same($rTag, Der::TAG_INTEGER);

        [$sTag, $sValue] = Der::readTlv($sequenceContent, $offsetAfterR);
        Assert::same($sTag, Der::TAG_INTEGER);

        $rHex = bin2hex(ltrim($rValue, "\x00"));
        $sHex = bin2hex(ltrim($sValue, "\x00"));

        Assert::stringNotEmpty($rHex);
        Assert::stringNotEmpty($sHex);

        return [$rHex, $sHex];
    }

    /** @return numeric-string */
    private static function hex2dec(string $hex): string
    {
        $dec = '0';
        foreach (str_split($hex) as $char) {
            $digit = (string) hexdec($char);

            $dec = bcadd(bcmul($dec, '16'), $digit);
        }

        return $dec;
    }

    /**
     * @param numeric-string $a
     * @param numeric-string $m
     *
     * @return numeric-string
     */
    private static function modinv(string $a, string $m): string
    {
        // a^-1 mod m == a^(m-2) mod m, by Fermat's little theorem (valid since m is prime for both P and N here)
        return bcpowmod($a, bcsub($m, '2'), $m);
    }

    /**
     * @param array{0: numeric-string, 1: numeric-string}|null $p1
     * @param array{0: numeric-string, 1: numeric-string}|null $p2
     * @param numeric-string                                   $p
     * @param numeric-string                                   $a
     *
     * @return array{0: numeric-string, 1: numeric-string}|null null represents the point at infinity
     */
    private static function pointAdd(array|null $p1, array|null $p2, string $p, string $a): array|null
    {
        if ($p1 === null) {
            return $p2;
        }

        if ($p2 === null) {
            return $p1;
        }

        [$x1, $y1] = $p1;
        [$x2, $y2] = $p2;

        if (bccomp($x1, $x2) === 0) {
            if (bccomp(bcmod(bcadd($y1, $y2), $p), '0') === 0) {
                return null;
            }

            $numerator   = bcmod(bcadd(bcmul('3', bcmul($x1, $x1)), $a), $p);
            $denominator = self::modinv(bcmod(bcmul('2', $y1), $p), $p);
        } else {
            $numerator   = bcmod(bcsub($y2, $y1), $p);
            $denominator = self::modinv(bcmod(bcsub($x2, $x1), $p), $p);
        }

        $lambda = bcmod(bcmul($numerator, $denominator), $p);

        $x3 = bcmod(bcsub(bcsub(bcmul($lambda, $lambda), $x1), $x2), $p);
        $y3 = bcmod(bcsub(bcmul($lambda, bcsub($x1, $x3)), $y1), $p);

        if (bccomp($x3, '0') < 0) {
            $x3 = bcadd($x3, $p);
        }

        if (bccomp($y3, '0') < 0) {
            $y3 = bcadd($y3, $p);
        }

        return [$x3, $y3];
    }

    /**
     * @param array{0: numeric-string, 1: numeric-string} $point
     * @param numeric-string                              $scalar
     * @param numeric-string                              $p
     * @param numeric-string                              $a
     *
     * @return array{0: numeric-string, 1: numeric-string}|null
     */
    private static function pointMultiply(array $point, string $scalar, string $p, string $a): array|null
    {
        $result = null;
        $addend = $point;
        $bits   = strrev(self::decToBin($scalar));

        for ($i = 0; $i < strlen($bits); $i++) {
            if ($bits[$i] === '1') {
                $result = self::pointAdd($result, $addend, $p, $a);
            }

            $addend = self::pointAdd($addend, $addend, $p, $a);
        }

        return $result;
    }

    /** @param numeric-string $decimal */
    private static function decToBin(string $decimal): string
    {
        $bits = '';
        while (bccomp($decimal, '0') > 0) {
            $bits    = bcmod($decimal, '2') . $bits;
            $decimal = bcdiv($decimal, '2', 0);
        }

        return $bits === '' ? '0' : $bits;
    }
}

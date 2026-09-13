<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use function bcadd;
use function bccomp;
use function bcdiv;
use function bcmod;
use function bcmul;
use function bcpowmod;
use function bcsub;
use function bin2hex;
use function hexdec;
use function str_split;
use function strlen;
use function strrev;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-import-type EcdsaCurve from EcdsaDigestVerifierBackend
 */
final class BcMathEcdsaDigestVerifierBackend implements EcdsaDigestVerifierBackend
{
    /** @param EcdsaCurve $curve */
    public function verify(array $curve, string $digest, string $rHex, string $sHex, string $qxBytes, string $qyBytes): bool
    {
        $p = self::hex2dec($curve['p']);
        $a = self::hex2dec($curve['a']);
        $n = self::hex2dec($curve['n']);

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

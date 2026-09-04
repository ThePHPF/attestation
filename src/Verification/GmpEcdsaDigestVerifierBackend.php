<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use GMP;

use function bin2hex;
use function gmp_add;
use function gmp_cmp;
use function gmp_div_q;
use function gmp_init;
use function gmp_invert;
use function gmp_mod;
use function gmp_mul;
use function gmp_sub;
use function gmp_testbit;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-import-type EcdsaCurve from EcdsaDigestVerifierBackend
 */
final class GmpEcdsaDigestVerifierBackend implements EcdsaDigestVerifierBackend
{
    /** @param EcdsaCurve $curve */
    public function verify(array $curve, string $digest, string $rHex, string $sHex, string $qxBytes, string $qyBytes): bool
    {
        $p = gmp_init($curve['p'], 16);
        $a = gmp_init($curve['a'], 16);
        $n = gmp_init($curve['n'], 16);

        $r = gmp_init($rHex, 16);
        $s = gmp_init($sHex, 16);

        if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, gmp_sub($n, 1)) > 0) {
            return false;
        }

        if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, gmp_sub($n, 1)) > 0) {
            return false;
        }

        $e = gmp_init(bin2hex($digest), 16);

        $w = gmp_invert($s, $n);
        if ($w === false) {
            return false;
        }

        $u1 = gmp_mod(gmp_mul($e, $w), $n);
        $u2 = gmp_mod(gmp_mul($r, $w), $n);

        $basePoint = [gmp_init($curve['gx'], 16), gmp_init($curve['gy'], 16)];
        $publicKey = [gmp_init(bin2hex($qxBytes), 16), gmp_init(bin2hex($qyBytes), 16)];

        $u1BasePoint = self::pointMultiply($basePoint, $u1, $p, $a);
        $u2PublicKey = self::pointMultiply($publicKey, $u2, $p, $a);

        $sum = self::pointAdd($u1BasePoint, $u2PublicKey, $p, $a);
        if ($sum === null) {
            return false;
        }

        [$x1] = $sum;

        return gmp_cmp(gmp_mod($x1, $n), $r) === 0;
    }

    /**
     * @param array{0: GMP, 1: GMP}|null $p1
     * @param array{0: GMP, 1: GMP}|null $p2
     *
     * @return array{0: GMP, 1: GMP}|null null represents the point at infinity
     */
    private static function pointAdd(array|null $p1, array|null $p2, GMP $p, GMP $a): array|null
    {
        if ($p1 === null) {
            return $p2;
        }

        if ($p2 === null) {
            return $p1;
        }

        [$x1, $y1] = $p1;
        [$x2, $y2] = $p2;

        if (gmp_cmp($x1, $x2) === 0) {
            if (gmp_cmp(gmp_mod(gmp_add($y1, $y2), $p), 0) === 0) {
                return null;
            }

            $numerator   = gmp_mod(gmp_add(gmp_mul(3, gmp_mul($x1, $x1)), $a), $p);
            $denominator = gmp_invert(gmp_mod(gmp_mul(2, $y1), $p), $p);
        } else {
            $numerator   = gmp_mod(gmp_sub($y2, $y1), $p);
            $denominator = gmp_invert(gmp_mod(gmp_sub($x2, $x1), $p), $p);
        }

        if ($denominator === false) {
            return null;
        }

        $lambda = gmp_mod(gmp_mul($numerator, $denominator), $p);

        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_mul($lambda, $lambda), $x1), $x2), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

        return [$x3, $y3];
    }

    /**
     * @param array{0: GMP, 1: GMP} $point
     *
     * @return array{0: GMP, 1: GMP}|null
     */
    private static function pointMultiply(array $point, GMP $scalar, GMP $p, GMP $a): array|null
    {
        $result    = null;
        $addend    = $point;
        $remaining = $scalar;

        while (gmp_cmp($remaining, 0) > 0) {
            if (gmp_testbit($remaining, 0)) {
                $result = self::pointAdd($result, $addend, $p, $a);
            }

            $addend    = self::pointAdd($addend, $addend, $p, $a);
            $remaining = gmp_div_q($remaining, 2);
        }

        return $result;
    }
}

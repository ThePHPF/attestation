<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid;
use ThePhpFoundation\Attestation\Verification\Exception\Rfc3161TimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampAuthorityCertificateOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid */
final class Rfc3161TimestampsAreValidTest extends TestCase
{
    private const TSA_VALIDITY_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/trust-root-tsa-validity-end-inclusive.json';
    private const TSA_VALIDITY_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/trust-root-tsa-validity-end-inclusive-trusted-root.json';

    private const UNTRUSTED_TSA_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/rekor2-timestamp-untrusted-tsa-with-embedded-cert-fail.json';
    private const UNTRUSTED_TSA_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/rekor2-timestamp-untrusted-tsa-with-embedded-cert-fail-trusted-root.json';

    private const TSA_CERT_VALIDITY_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/rekor2-timestamp-outside-tsa-cert-validity-fail.json';
    private const TSA_CERT_VALIDITY_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/rekor2-timestamp-outside-tsa-cert-validity-fail-trusted-root.json';

    private static function bundle(string $fixturePath): Bundle
    {
        $contents = file_get_contents($fixturePath);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsAnRfc3161TimestampExactlyAtTheTimestampAuthoritysValidityEnd(): void
    {
        $check = new Rfc3161TimestampsAreValid(new TrustedRoot(self::TSA_VALIDITY_TRUSTED_ROOT_FIXTURE));

        $this->expectNotToPerformAssertions();
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(self::TSA_VALIDITY_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsAnRfc3161TimestampSignedByAnUntrustedTimestampAuthority(): void
    {
        $check = new Rfc3161TimestampsAreValid(new TrustedRoot(self::UNTRUSTED_TSA_TRUSTED_ROOT_FIXTURE));

        $this->expectException(Rfc3161TimestampVerificationFailed::class);
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(self::UNTRUSTED_TSA_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsAnRfc3161TimestampOutsideTheTimestampAuthorityCertificatesOwnValidityWindow(): void
    {
        $check = new Rfc3161TimestampsAreValid(new TrustedRoot(self::TSA_CERT_VALIDITY_TRUSTED_ROOT_FIXTURE));

        $this->expectException(TimestampAuthorityCertificateOutsideValidityPeriod::class);
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(self::TSA_CERT_VALIDITY_BUNDLE_FIXTURE),
        );
    }
}

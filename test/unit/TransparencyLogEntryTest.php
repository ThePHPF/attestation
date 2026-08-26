<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\InclusionProof;
use ThePhpFoundation\Attestation\TransparencyLogEntry;
use Webmozart\Assert\Assert;

use function base64_decode;
use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\TransparencyLogEntry */
final class TransparencyLogEntryTest extends TestCase
{
    private const NEGATIVE_LOG_INDEX_BUNDLE_FIXTURE = __DIR__ . '/../fixture/bundle-negative-log-index-fail.json';

    public function testFromBundleTransparencyLogEntry(): void
    {
        $transparencyLogEntry = TransparencyLogEntry::fromBundleTransparencyLogEntry([
            'logIndex' => '461079899',
            'logId' => ['keyId' => 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0='],
            'kindVersion' => ['kind' => 'dsse', 'version' => '0.0.1'],
            'integratedTime' => '1756846563',
            'inclusionPromise' => ['signedEntryTimestamp' => 'MEQCIGpzZ0f+u9PWHz14hQpE8ZE2TT6TDqlIVNN6JKCRRALLAiAmqBkeImJEJLHrUfLsvwBRjaVngZcjvji/d6+VUnkRZQ=='],
            'inclusionProof' => [
                'logIndex' => '339175637',
                'rootHash' => 'AhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4=',
                'treeSize' => '339175655',
                'hashes' => [],
            ],
            'canonicalizedBody' => 'eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==',
        ]);

        self::assertSame(461079899, $transparencyLogEntry->logIndex);
        self::assertSame(1756846563, $transparencyLogEntry->integratedTime);
        self::assertSame('dsse', $transparencyLogEntry->kind);
        self::assertSame(base64_decode('wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0='), $transparencyLogEntry->logId);
        self::assertSame(base64_decode('eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ=='), $transparencyLogEntry->canonicalizedBody);
        self::assertSame(
            base64_decode('MEQCIGpzZ0f+u9PWHz14hQpE8ZE2TT6TDqlIVNN6JKCRRALLAiAmqBkeImJEJLHrUfLsvwBRjaVngZcjvji/d6+VUnkRZQ=='),
            $transparencyLogEntry->signedEntryTimestamp,
        );
        self::assertInstanceOf(InclusionProof::class, $transparencyLogEntry->inclusionProof);
        self::assertSame(339175637, $transparencyLogEntry->inclusionProof->logIndex);
    }

    public function testFromBundleTransparencyLogEntryWithoutInclusionProof(): void
    {
        $contents = file_get_contents(self::NEGATIVE_LOG_INDEX_BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]);

        $transparencyLogEntry = TransparencyLogEntry::fromBundleTransparencyLogEntry(
            $decoded['verificationMaterial']['tlogEntries'][0],
        );

        self::assertNull($transparencyLogEntry->inclusionProof);
    }
}

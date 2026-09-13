<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function in_array;
use function json_decode;
use function openssl_x509_parse;
use function substr;

/** @covers \ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions */
final class FulcioSigstoreOidExtensionsTest extends TestCase
{
    private const BUNDLE_FIXTURE = __DIR__ . '/../fixture/bundle.json';

    private const PLAIN_STRING_OIDS = [
        FulcioSigstoreOidExtensions::ISSUER_V1,
        FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_TRIGGER,
        FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_SHA,
        FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_NAME,
        FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REPOSITORY,
        FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REF,
    ];

    /** @return array<non-empty-string, array{0: non-empty-string, 1: non-empty-string}> [constant name => [constant value, expected OID]] */
    public static function constantProvider(): array
    {
        return [
            'ISSUER_V1' => [FulcioSigstoreOidExtensions::ISSUER_V1, '1.3.6.1.4.1.57264.1.1'],
            'GITHUB_WORKFLOW_TRIGGER' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_TRIGGER, '1.3.6.1.4.1.57264.1.2'],
            'GITHUB_WORKFLOW_SHA' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_SHA, '1.3.6.1.4.1.57264.1.3'],
            'GITHUB_WORKFLOW_NAME' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_NAME, '1.3.6.1.4.1.57264.1.4'],
            'GITHUB_WORKFLOW_REPOSITORY' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REPOSITORY, '1.3.6.1.4.1.57264.1.5'],
            'GITHUB_WORKFLOW_REF' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REF, '1.3.6.1.4.1.57264.1.6'],
            'OTHER_NAME_SAN' => [FulcioSigstoreOidExtensions::OTHER_NAME_SAN, '1.3.6.1.4.1.57264.1.7'],
            'ISSUER_V2' => [FulcioSigstoreOidExtensions::ISSUER_V2, '1.3.6.1.4.1.57264.1.8'],
            'BUILD_SIGNER_URI' => [FulcioSigstoreOidExtensions::BUILD_SIGNER_URI, '1.3.6.1.4.1.57264.1.9'],
            'BUILD_SIGNER_DIGEST' => [FulcioSigstoreOidExtensions::BUILD_SIGNER_DIGEST, '1.3.6.1.4.1.57264.1.10'],
            'RUNNER_ENVIRONMENT' => [FulcioSigstoreOidExtensions::RUNNER_ENVIRONMENT, '1.3.6.1.4.1.57264.1.11'],
            'SOURCE_REPOSITORY_URI' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI, '1.3.6.1.4.1.57264.1.12'],
            'SOURCE_REPOSITORY_DIGEST' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_DIGEST, '1.3.6.1.4.1.57264.1.13'],
            'SOURCE_REPOSITORY_REF' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_REF, '1.3.6.1.4.1.57264.1.14'],
            'SOURCE_REPOSITORY_IDENTIFIER' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_IDENTIFIER, '1.3.6.1.4.1.57264.1.15'],
            'SOURCE_REPOSITORY_OWNER_URI' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI, '1.3.6.1.4.1.57264.1.16'],
            'SOURCE_REPOSITORY_OWNER_IDENTIFIER' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_IDENTIFIER, '1.3.6.1.4.1.57264.1.17'],
            'BUILD_CONFIG_URI' => [FulcioSigstoreOidExtensions::BUILD_CONFIG_URI, '1.3.6.1.4.1.57264.1.18'],
            'BUILD_CONFIG_DIGEST' => [FulcioSigstoreOidExtensions::BUILD_CONFIG_DIGEST, '1.3.6.1.4.1.57264.1.19'],
            'BUILD_TRIGGER' => [FulcioSigstoreOidExtensions::BUILD_TRIGGER, '1.3.6.1.4.1.57264.1.20'],
            'RUN_INVOCATION_URI' => [FulcioSigstoreOidExtensions::RUN_INVOCATION_URI, '1.3.6.1.4.1.57264.1.21'],
            'SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING, '1.3.6.1.4.1.57264.1.22'],
            'DEPLOYMENT_ENVIRONMENT' => [FulcioSigstoreOidExtensions::DEPLOYMENT_ENVIRONMENT, '1.3.6.1.4.1.57264.1.23'],
            'TOKEN_SUBJECT' => [FulcioSigstoreOidExtensions::TOKEN_SUBJECT, '1.3.6.1.4.1.57264.1.24'],
        ];
    }

    /** @dataProvider constantProvider */
    public function testConstantHasItsExpectedOidValue(string $actualOid, string $expectedOid): void
    {
        self::assertSame($expectedOid, $actualOid);
    }

    /** @return array<non-empty-string, array{0: non-empty-string, 1: non-empty-string}> [constant name => [OID, expected decoded value]] */
    public static function realCertificateExtensionProvider(): array
    {
        return [
            'ISSUER_V1' => [FulcioSigstoreOidExtensions::ISSUER_V1, 'https://token.actions.githubusercontent.com'],
            'GITHUB_WORKFLOW_TRIGGER' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_TRIGGER, 'release'],
            'GITHUB_WORKFLOW_SHA' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_SHA, '4b20e778e116a3e77ece8ad26d4a44dd64bbeaf6'],
            'GITHUB_WORKFLOW_NAME' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_NAME, 'Publish the PHAR for Releases'],
            'GITHUB_WORKFLOW_REPOSITORY' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REPOSITORY, 'php/pie'],
            'GITHUB_WORKFLOW_REF' => [FulcioSigstoreOidExtensions::GITHUB_WORKFLOW_REF, 'refs/tags/1.2.0'],
            'ISSUER_V2' => [FulcioSigstoreOidExtensions::ISSUER_V2, 'https://token.actions.githubusercontent.com'],
            'BUILD_SIGNER_URI' => [FulcioSigstoreOidExtensions::BUILD_SIGNER_URI, 'https://github.com/php/pie/.github/workflows/build-phar.yml@refs/tags/1.2.0'],
            'BUILD_SIGNER_DIGEST' => [FulcioSigstoreOidExtensions::BUILD_SIGNER_DIGEST, '4b20e778e116a3e77ece8ad26d4a44dd64bbeaf6'],
            'RUNNER_ENVIRONMENT' => [FulcioSigstoreOidExtensions::RUNNER_ENVIRONMENT, 'github-hosted'],
            'SOURCE_REPOSITORY_URI' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI, 'https://github.com/php/pie'],
            'SOURCE_REPOSITORY_DIGEST' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_DIGEST, '4b20e778e116a3e77ece8ad26d4a44dd64bbeaf6'],
            'SOURCE_REPOSITORY_REF' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_REF, 'refs/tags/1.2.0'],
            'SOURCE_REPOSITORY_IDENTIFIER' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_IDENTIFIER, '765049687'],
            'SOURCE_REPOSITORY_OWNER_URI' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI, 'https://github.com/php'],
            'SOURCE_REPOSITORY_OWNER_IDENTIFIER' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_IDENTIFIER, '25158'],
            'BUILD_CONFIG_URI' => [FulcioSigstoreOidExtensions::BUILD_CONFIG_URI, 'https://github.com/php/pie/.github/workflows/release.yml@refs/tags/1.2.0'],
            'BUILD_CONFIG_DIGEST' => [FulcioSigstoreOidExtensions::BUILD_CONFIG_DIGEST, '4b20e778e116a3e77ece8ad26d4a44dd64bbeaf6'],
            'BUILD_TRIGGER' => [FulcioSigstoreOidExtensions::BUILD_TRIGGER, 'release'],
            'RUN_INVOCATION_URI' => [FulcioSigstoreOidExtensions::RUN_INVOCATION_URI, 'https://github.com/php/pie/actions/runs/17415751132/attempts/1'],
            'SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING' => [FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING, 'public'],
        ];
    }

    /** @dataProvider realCertificateExtensionProvider */
    public function testConstantMatchesTheRealValueOnAFulcioCertificate(string $oid, string $expectedValue): void
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        $certificateInfo = openssl_x509_parse(Bundle::fromBundle($decoded)->certificate()->decoratedCertificate());
        Assert::isArray($certificateInfo);
        Assert::isArray($certificateInfo['extensions']);
        Assert::keyExists($certificateInfo['extensions'], $oid);
        $rawValue = $certificateInfo['extensions'][$oid];
        Assert::stringNotEmpty($rawValue);

        $actualValue = in_array($oid, self::PLAIN_STRING_OIDS, true) ? $rawValue : substr($rawValue, 2);

        self::assertSame($expectedValue, $actualValue);
    }
}

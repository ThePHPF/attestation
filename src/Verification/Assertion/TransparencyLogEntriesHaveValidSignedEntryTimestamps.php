<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\SignedEntryTimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\TransparencyLogSignature;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function base64_encode;
use function bin2hex;
use function json_encode;

use const JSON_UNESCAPED_SLASHES;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @link https://github.com/sigstore/rekor/blob/main/pkg/util/signed_note.go
 */
final class TransparencyLogEntriesHaveValidSignedEntryTimestamps implements VerifyBundleCheck
{
    public function __construct(private TrustedRoot $trustedRoot)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $signedEntryTimestamp = $transparencyLogEntry->signedEntryTimestamp();
            $integratedTime       = $transparencyLogEntry->integratedTime();
            if ($signedEntryTimestamp === null || $integratedTime === null) {
                continue;
            }

            $transparencyLogKey = $this->trustedRoot->resolveTransparencyLogPublicKey($transparencyLogEntry->logId());

            $signedContent = json_encode(
                [
                    'body' => base64_encode($transparencyLogEntry->canonicalizedBody()),
                    'integratedTime' => $integratedTime,
                    'logID' => bin2hex($transparencyLogEntry->logId()),
                    'logIndex' => $transparencyLogEntry->logIndex(),
                ],
                JSON_UNESCAPED_SLASHES,
            );
            Assert::stringNotEmpty($signedContent);

            if (! TransparencyLogSignature::verify($transparencyLogKey, $signedContent, $signedEntryTimestamp)) {
                throw SignedEntryTimestampVerificationFailed::forIndex($bundleIndex);
            }
        }
    }
}

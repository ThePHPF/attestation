<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function ord;
use function strlen;
use function substr;

final class CertificateHasATrustedSignedCertificateTimestamp implements VerifyBundleCheck
{
    /** @link https://www.rfc-editor.org/rfc/rfc6962#section-3.3 */
    private const CT_PRECERT_SCTS_EXTENSION_OID_DER = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";

    private TrustedRoot $trustedRoot;

    public function __construct(TrustedRoot $trustedRoot)
    {
        $this->trustedRoot = $trustedRoot;
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $logIds = $this->extractSignedCertificateTimestampLogIds($bundle->certificate()->derEncodedBytes());

        foreach ($logIds as $logId) {
            if ($this->trustedRoot->isCertificateTransparencyLogIdTrusted($logId)) {
                return;
            }
        }

        throw UntrustedCertificateTransparencyLogKey::new();
    }

    /** @return non-empty-list<non-empty-string> */
    private function extractSignedCertificateTimestampLogIds(string $certificateDer): array
    {
        [$certTag, $certContent] = Der::readTlv($certificateDer, 0);
        Assert::same($certTag, Der::TAG_SEQUENCE);

        [$tbsTag, $tbsContent] = Der::readTlv($certContent, 0);
        Assert::same($tbsTag, Der::TAG_SEQUENCE);

        $extensionsBlock = null;
        $offset          = 0;
        while ($offset < strlen($tbsContent)) {
            [$fieldTag, $fieldValue, $offset] = Der::readTlv($tbsContent, $offset);
            if ($fieldTag !== Der::TAG_CONTEXT_EXTENSIONS) {
                continue;
            }

            $extensionsBlock = $fieldValue;
        }

        Assert::stringNotEmpty($extensionsBlock);

        [$extSeqTag, $extSeqContent] = Der::readTlv($extensionsBlock, 0);
        Assert::same($extSeqTag, Der::TAG_SEQUENCE);

        $sctExtensionValue = null;
        $offset            = 0;
        while ($offset < strlen($extSeqContent)) {
            [$extTag, $extContent, $offset] = Der::readTlv($extSeqContent, $offset);
            if ($extTag !== Der::TAG_SEQUENCE) {
                continue;
            }

            [$oidTag, $oidValue, $innerOffset] = Der::readTlv($extContent, 0);
            Assert::same($oidTag, Der::TAG_OBJECT_IDENTIFIER);
            if ($oidValue !== self::CT_PRECERT_SCTS_EXTENSION_OID_DER) {
                continue;
            }

            [$nextTag, $nextValue, $innerOffset] = Der::readTlv($extContent, $innerOffset);
            if ($nextTag === Der::TAG_BOOLEAN) {
                [$nextTag, $nextValue] = Der::readTlv($extContent, $innerOffset);
            }

            Assert::same($nextTag, Der::TAG_OCTET_STRING);
            $sctExtensionValue = $nextValue;
        }

        Assert::stringNotEmpty($sctExtensionValue);

        [$innerOctetStringTag, $sctList] = Der::readTlv($sctExtensionValue, 0);
        Assert::same($innerOctetStringTag, Der::TAG_OCTET_STRING);
        Assert::true(strlen($sctList) >= 2);

        $logIds = [];
        $offset = 2; // Skip the 2-byte total-length prefix of the SignedCertificateTimestampList.
        while ($offset < strlen($sctList)) {
            Assert::true($offset + 2 <= strlen($sctList));
            $sctLength = (ord($sctList[$offset]) << 8) | ord($sctList[$offset + 1]);
            $offset   += 2;

            Assert::true($offset + $sctLength <= strlen($sctList));
            $sct     = substr($sctList, $offset, $sctLength);
            $offset += $sctLength;

            // SignedCertificateTimestamp ::= version(1) || log_id(32) || timestamp(8) || extensions(...) || signature(...)
            Assert::true(strlen($sct) >= 33);
            $logId = substr($sct, 1, 32);
            Assert::stringNotEmpty($logId);
            $logIds[] = $logId;
        }

        Assert::isNonEmptyList($logIds);

        return $logIds;
    }
}

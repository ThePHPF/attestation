<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

/**
 * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#136141572641--fulcio
 *
 * @todo change to an enum in PHP 8.1
 */
final class Extension
{
    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2 */
    public const ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264112--source-repository-uri */
    public const SOURCE_REPOSITORY_URI = '1.3.6.1.4.1.57264.1.12';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264116--source-repository-owner-uri */
    public const SOURCE_REPOSITORY_OWNER_URI = '1.3.6.1.4.1.57264.1.16';
}

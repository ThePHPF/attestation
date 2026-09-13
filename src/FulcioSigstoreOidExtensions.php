<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

/**
 * Some of the Fulcio Sigstore OID extensions.
 *
 * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#136141572641--fulcio
 */
final class FulcioSigstoreOidExtensions
{
    /**
     * @deprecated use {@see ISSUER_V2} instead
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726411--issuer-deprecated
     */
    public const ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';

    /**
     * @deprecated use {@see BUILD_TRIGGER} instead
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726412--github-workflow-trigger-deprecated
     */
    public const GITHUB_WORKFLOW_TRIGGER = '1.3.6.1.4.1.57264.1.2';

    /**
     * @deprecated use {@see SOURCE_REPOSITORY_DIGEST} instead
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726413--github-workflow-sha-deprecated
     */
    public const GITHUB_WORKFLOW_SHA = '1.3.6.1.4.1.57264.1.3';

    /**
     * @deprecated no replacement offered
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726414--github-workflow-name-deprecated
     */
    public const GITHUB_WORKFLOW_NAME = '1.3.6.1.4.1.57264.1.4';

    /**
     * @deprecated use {@see SOURCE_REPOSITORY_URI} instead
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726415--github-workflow-repository-deprecated
     */
    public const GITHUB_WORKFLOW_REPOSITORY = '1.3.6.1.4.1.57264.1.5';

    /**
     * @deprecated use {@see SOURCE_REPOSITORY_REF} instead
     *
     * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726416--github-workflow-ref-deprecated
     */
    public const GITHUB_WORKFLOW_REF = '1.3.6.1.4.1.57264.1.6';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726417--othername-san */
    public const OTHER_NAME_SAN = '1.3.6.1.4.1.57264.1.7';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2 */
    public const ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726419--build-signer-uri */
    public const BUILD_SIGNER_URI = '1.3.6.1.4.1.57264.1.9';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264110--build-signer-digest */
    public const BUILD_SIGNER_DIGEST = '1.3.6.1.4.1.57264.1.10';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264111--runner-environment */
    public const RUNNER_ENVIRONMENT = '1.3.6.1.4.1.57264.1.11';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264112--source-repository-uri */
    public const SOURCE_REPOSITORY_URI = '1.3.6.1.4.1.57264.1.12';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264113--source-repository-digest */
    public const SOURCE_REPOSITORY_DIGEST = '1.3.6.1.4.1.57264.1.13';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264114--source-repository-ref */
    public const SOURCE_REPOSITORY_REF = '1.3.6.1.4.1.57264.1.14';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264115--source-repository-identifier */
    public const SOURCE_REPOSITORY_IDENTIFIER = '1.3.6.1.4.1.57264.1.15';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264116--source-repository-owner-uri */
    public const SOURCE_REPOSITORY_OWNER_URI = '1.3.6.1.4.1.57264.1.16';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264117--source-repository-owner-identifier */
    public const SOURCE_REPOSITORY_OWNER_IDENTIFIER = '1.3.6.1.4.1.57264.1.17';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264118--build-config-uri */
    public const BUILD_CONFIG_URI = '1.3.6.1.4.1.57264.1.18';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264119--build-config-digest */
    public const BUILD_CONFIG_DIGEST = '1.3.6.1.4.1.57264.1.19';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264120--build-trigger */
    public const BUILD_TRIGGER = '1.3.6.1.4.1.57264.1.20';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264121--run-invocation-uri */
    public const RUN_INVOCATION_URI = '1.3.6.1.4.1.57264.1.21';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264122--source-repository-visibility-at-signing */
    public const SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING = '1.3.6.1.4.1.57264.1.22';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264123--deployment-environment */
    public const DEPLOYMENT_ENVIRONMENT = '1.3.6.1.4.1.57264.1.23';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264124--token-subject */
    public const TOKEN_SUBJECT = '1.3.6.1.4.1.57264.1.24';
}

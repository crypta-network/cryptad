#!/usr/bin/env python3
"""Run deterministic multi-node beta soak and upgrade-drill evidence.

The default simulated run is offline, deterministic, and safe for PR checks.
Hybrid runs can attach existing summaries, and live runs may check localhost
node reachability when explicitly requested.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import ipaddress
import io
import json
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CONFIG_KIND = "cryptad-multi-node-beta-soak-config"
PLAN_KIND = "cryptad-multi-node-beta-soak-plan"
SUMMARY_KIND = "cryptad-multi-node-beta-soak-summary"
PREVIOUS_CANDIDATE_SUMMARY_KIND = "cryptad-previous-beta-candidate-summary"
PREVIOUS_CANDIDATE_SUMMARY_KINDS = frozenset({PREVIOUS_CANDIDATE_SUMMARY_KIND})
SUMMARY_FILE_NAME = "multi-node-beta-soak-summary.json"
COMPAT_SUMMARY_FILE_NAME = "summary.json"
REPORT_FILE_NAME = "multi-node-beta-soak-summary.md"
PREVIOUS_CANDIDATE_REPORT_FILE_NAME = "previous-beta-candidate-summary.md"
FIXTURE_NAME = "self-test-multi-node-beta-soak.json"
PREVIOUS_CANDIDATE_FIXTURE_NAME = "previous-beta-candidate-summary-valid.json"
MODES = ("simulated", "hybrid", "live")
DURATION_PROFILES = ("ci-smoke", "rc-soak", "24h-soak")
CATALOG_CHANNELS = ("stable", "beta", "nightly", "deprecated")
BLOCKED_CATALOG_CHANNELS = frozenset({"nightly", "deprecated"})
NODE_ROLES = ("publisher", "subscriber", "bridge", "observer", "seed")
FIRST_PARTY_APPS = (
    "feed-reader",
    "profile-publisher",
    "trust-graph",
    "social-inbox",
)
REQUIRED_LIFECYCLE_APPS = ("feed-reader", "social-inbox", "trust-graph")
PREVIOUS_CANDIDATE_REQUIRED_APPS = (
    "feed-reader",
    "profile-publisher",
    "trust-graph",
    "social-inbox",
)
PREVIOUS_CANDIDATE_MIGRATION_APPS = ("feed-reader", "social-inbox", "trust-graph")
PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS = (
    "catalog",
    "platformApi",
    "firstPartyApps",
    "appData",
    "trustGraph",
    "socialInbox",
    "supportBundle",
    "redaction",
)
PREVIOUS_CANDIDATE_DRILL_DIGEST_FIELDS = (
    "schemaVersion",
    "kind",
    "releaseId",
    "version",
    *PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS,
)
PREVIOUS_CANDIDATE_SOURCE_METADATA_CONTAINERS = (
    "previousCandidateMetadata",
    "previousBetaCandidateMetadata",
    "previousCandidateSummary",
    "previousBetaCandidateSummary",
)
RELEASE_CERTIFICATION_TOOL_NAME = "release-certification"
PRODUCTION_BETA_TOOL_NAME = "production-beta-release"
PRODUCTION_BETA_SUMMARY_KINDS = frozenset({"cryptad-production-beta-release-summary"})
REQUIRED_SCENARIOS = (
    "catalogUpdate",
    "appInstallUpdateRollback",
    "appDataMigration",
    "backupRestore",
    "subscriptionPressure",
    "trustGraphImport",
    "socialInboxMultiSource",
    "supportBundleDrill",
    "upgradeFromPreviousCandidate",
)
SCENARIO_IDS = {
    "catalogUpdate": "catalog-channel-update",
    "appInstallUpdateRollback": "app-install-update-rollback",
    "appDataMigration": "app-data-migration",
    "backupRestore": "backup-restore",
    "subscriptionPressure": "subscription-pressure",
    "trustGraphImport": "trust-graph-import",
    "socialInboxMultiSource": "social-inbox-multi-source",
    "supportBundleDrill": "support-bundle-drill",
    "upgradeFromPreviousCandidate": "upgrade-from-previous-candidate",
}
SCENARIO_EVIDENCE_IDS = {
    "catalog-channel-update": "multi-node-beta.catalog-channel-update",
    "app-install-update-rollback": "multi-node-beta.app-install-update-rollback",
    "app-data-migration": "multi-node-beta.app-data-migration",
    "backup-restore": "multi-node-beta.backup-restore",
    "subscription-pressure": "multi-node-beta.subscription-pressure",
    "trust-graph-import": "multi-node-beta.trust-graph-import",
    "social-inbox-multi-source": "multi-node-beta.social-inbox-multi-source",
    "support-bundle-drill": "multi-node-beta.support-bundle-drill",
    "upgrade-from-previous-candidate": "multi-node-beta.upgrade-drill",
}
EVIDENCE_IDS = (
    "multi-node-beta.soak",
    "multi-node-beta.upgrade-drill",
    "multi-node-beta.catalog-channel-update",
    "multi-node-beta.app-install-update-rollback",
    "multi-node-beta.app-data-migration",
    "multi-node-beta.backup-restore",
    "multi-node-beta.subscription-pressure",
    "multi-node-beta.trust-graph-import",
    "multi-node-beta.social-inbox-multi-source",
    "multi-node-beta.support-bundle-drill",
    "multi-node-beta.redaction",
)
REQUIRED_SCENARIO_EVIDENCE_FIELDS = {
    "catalog-channel-update": (
        "stableOnlyNodeCount",
        "betaOptInNodeCount",
        "stableNodesBlockBetaAndNightly",
        "betaNodesOptInExplicitly",
        "nightlyCandidatesBlocked",
        "deprecatedCandidatesBlocked",
        "denylistedCandidatesBlocked",
        "nodesWithBlockedCatalogChannels",
        "catalogSignatureEvidence",
        "privateInsertUrisIncluded",
    ),
    "app-install-update-rollback": (
        "installedFirstPartyApps",
        "updatedApps",
        "missingRequiredApps",
        "rollbackApp",
        "healthFailureSimulated",
        "rollbackAvailable",
        "rollbackResult",
        "majorDeltaConsentGatePreserved",
        "autoUpdateBypassedConsent",
    ),
    "app-data-migration": (
        "apps",
        "failedMigrationBlocksUpdate",
        "failedMigrationTriggersRollback",
        "metadataOnly",
    ),
    "backup-restore": (
        "exportedApps",
        "restoredIntoCleanNodeId",
        "manifestSchemaCompatible",
        "restoreDigest",
        "supportExportSeparateFromBackupBundle",
        "vaultPrivateIdentityMaterialIncluded",
        "rawBackupPayloadIncluded",
    ),
    "subscription-pressure": (
        "nodesCovered",
        "uskSubscriptionCount",
        "queuePressureEvents",
        "backoffDecisions",
        "globalFetchPolicyRespected",
        "rawFetchedContentIncluded",
        "queueHtmlIncluded",
    ),
    "trust-graph-import": (
        "signedStatementImportsAttempted",
        "acceptedStatements",
        "duplicateStatementsSummarized",
        "hostileInputsRejected",
        "oversizedInputsRejected",
        "statementDigestSet",
        "scoreExplanationLimit",
        "localScopeMessagingPreserved",
        "rawTrustStatementsIncluded",
    ),
    "social-inbox-multi-source": (
        "sourceCount",
        "threadCount",
        "dedupedMessageCount",
        "readStateTransitions",
        "trustScoreAnnotationsViaGrant",
        "grantRevokedDegradesSafely",
        "rawMessageBodiesIncluded",
    ),
    "support-bundle-drill": (
        "generatedAfterFailedUpdate",
        "generatedAfterSubscriptionPressure",
        "generatedAfterSecurityAdvisory",
        "supportBundleDigest",
        "redactionScanStatus",
        "secretsIncluded",
        "rawContentIncluded",
        "rawAppDataIncluded",
        "absolutePathsIncluded",
        "tokensIncluded",
        "privateInsertUrisIncluded",
        "appleDoubleArtifactsIncluded",
    ),
    "upgrade-from-previous-candidate": (
        "previousVersion",
        "currentVersion",
        "previousReleaseId",
        "previousSummaryDrillDigest",
        "previousCatalogChannel",
        "currentCatalogChannel",
        "previousStableCatalogEdition",
        "previousBetaCatalogEdition",
        "currentCatalogEdition",
        "previousSummaryConfigured",
        "previousSummaryProvided",
        "previousSummaryValid",
        "previousSummaryValidationErrors",
        "previousSummaryStatus",
        "currentProductionBetaSummaryConfigured",
        "currentProductionBetaSummaryProvided",
        "currentProductionBetaSummaryValid",
        "currentProductionBetaValidationErrors",
        "currentProductionBetaStatus",
        "currentUpgradePathRepresented",
        "daemonUpgrade",
        "appMigrations",
        "backupRestore",
        "failedMigration",
        "socialInboxMigration",
        "trustGraphMigration",
        "supportBundleAfterFailedUpgrade",
        "firstPartyAppMigrationStatus",
        "backupBeforeUpdateStatus",
        "restoreIntoCleanNodeStatus",
        "socialInboxMigrationStatus",
        "trustGraphMigrationStatus",
        "supportBundleRedactionStatus",
        "rollbackStatus",
        "rawDataIncluded",
        "releaseReport",
        "strictPreviousSummaryRequired",
    ),
}
REDACTION_KEYS = (
    "failOnPrivateInsertUri",
    "failOnRawFetchedContent",
    "failOnTokens",
    "failOnAbsoluteLocalPaths",
)
STRICT_KEYS = ("requirePreviousSummary", "requireAllScenarios")
SAFE_SUMMARY_ARTIFACT_KEYS = ("markdownReport", "rawSummary")
DETERMINISTIC_GENERATED_AT = "1970-01-01T00:00:00Z"
PLACEHOLDER_ARTIFACT_HOSTS = {"downloads.crypta.invalid"}
LOCAL_ARTIFACT_HOSTS = {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}
PRIVATE_ARTIFACT_HOST_SUFFIXES = (
    ".invalid",
    ".localhost",
    ".local",
    ".localdomain",
    ".lan",
    ".home",
    ".corp",
    ".internal",
    ".test",
    ".example",
)

PRIVATE_INSERT_URI_RE = re.compile(
    r"(?:"
    r"\b(?:crypta:|freenet:)?(?:SSK|USK)@[^/,\s\"'<>)]*(?:PRIVATE|INSERT|AQECAAE)[^\s\"'<>)]*"
    r"|"
    r"(?<![\w-])(?:private[-_ ]*)?insert(?:[-_ ]*uri)?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?"
    r"(?:crypta:|freenet:)?(?:SSK|USK)@(?=[A-Za-z0-9~_-]{8,},)[A-Za-z0-9~_,=-]+"
    r")",
    re.IGNORECASE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
AUTH_HEADER_RE = re.compile(
    r"(?<![\w-])[\"']?Authorization[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*[\"']?(?:Bearer|Basic|Digest)?\s*([^\s,'\"}]+)",
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
TOKEN_VALUE_RE = re.compile(
    r"(?<![\w-])(?:CRYPTAD_APP_TOKEN|browserSessionToken|appProcessToken|"
    r"X-Crypta-App-Session|app[-_ ]?token|browser[-_ ]?session[-_ ]?token|session[-_ ]?token)"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
FORM_PASSWORD_VALUE_RE = re.compile(
    r"(?:(?<![\w-])--form-password(?:=|\s+)|"
    r"(?<![\w-])[\"']?(?:X-Crypta-Form-Password|CRYPTAD_CERT_FORM_PASSWORD|"
    r"formPassword|form[-_ ]?password)[\"']?(?![\w-])"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*)['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
CI_SECRET_VALUE_RE = re.compile(
    r"(?<![\w-])[\"']?(?:GITHUB_TOKEN|SONAR_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|AWS_SECRET_ACCESS_KEY|"
    r"CRYPTAD_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|INSERT_URI)[A-Z0-9_]*)"
    r"[\"']?(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\s,;&}]+)",
    re.IGNORECASE,
)
RAW_FETCHED_CONTENT_RE = re.compile(
    r"(?<![\w-])(?:rawFetchedContent|raw[-_ ]*fetched[-_ ]*(?:body|content|payload)|"
    r"fetched[-_ ]*raw[-_ ]*(?:body|content|payload))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
RAW_APP_DATA_RE = re.compile(
    r"(?<![\w-])(?:rawAppData|raw[-_ ]*app[-_ ]*data[-_ ]*(?:value|values|payload)|"
    r"app[-_ ]*data[-_ ]*raw[-_ ]*(?:value|values|payload))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
RAW_SOCIAL_MESSAGE_RE = re.compile(
    r"(?<![\w-])(?:rawMessageBody|raw[-_ ]*(?:social[-_ ]*)?(?:message|mail)[-_ ]*"
    r"(?:body|content|payload)|(?:social[-_ ]*)?(?:message|mail)[-_ ]*raw[-_ ]*"
    r"(?:body|content|payload))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
RAW_TRUST_STATEMENT_RE = re.compile(
    r"(?<![\w-])(?:rawTrustStatements?|raw[-_ ]*trust[-_ ]*statement[-_ ]*"
    r"(?:body|content|payload|value)|trust[-_ ]*statement[-_ ]*raw[-_ ]*"
    r"(?:body|content|payload|value))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
RAW_BACKUP_PAYLOAD_RE = re.compile(
    r"(?<![\w-])(?:rawBackupPayload|raw[-_ ]*backup[-_ ]*(?:bundle|data|payload|value)|"
    r"backup[-_ ]*raw[-_ ]*(?:bundle|data|payload|value))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
RAW_SIGNATURE_RE = re.compile(
    r"(?<![\w-])(?:rawSignature|raw[-_ ]*signature[-_ ]*(?:bytes|payload|value)|"
    r"signature[-_ ]*raw[-_ ]*(?:bytes|payload|value))"
    r"(?![\w-])\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?([^'\"\r\n}]+)",
    re.IGNORECASE,
)
FILE_URI_RE = re.compile(r"\bfile:(?://[^/\s\"'<>]*)?/[^\s\"'<>]+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])[A-Za-z]:[\\/][^:*?\"<>|\r\n]+")
POSIX_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\-><])/(?!/)[^\s\"'<>),;{}]+"
)
SAFE_ROUTE_PREFIXES = ("/api/v1", "/app/node", "/apps")
REDACTED_SENTINELS = {
    "<redacted>",
    "redacted",
    "[redacted]",
    "<masked>",
    "masked",
    "[masked]",
    "***",
    "null",
    "undefined",
}
SENSITIVE_SAFETY_FLAG_MARKERS = (
    "absolute",
    "appledouble",
    "authorization",
    "browser",
    "credential",
    "inserturi",
    "macosx",
    "password",
    "path",
    "private",
    "queuehtml",
    "raw",
    "secret",
    "token",
    "vault",
)


DEFAULT_CONFIG: dict[str, Any] = {
    "schemaVersion": SCHEMA_VERSION,
    "kind": CONFIG_KIND,
    "mode": "simulated",
    "durationProfile": "ci-smoke",
    "previousCandidate": {
        "version": "previous-beta",
        "summaryPath": "",
        "catalogChannel": "stable",
    },
    "currentCandidate": {
        "version": "current-beta",
        "productionBetaSummaryPath": "",
        "catalogChannel": "stable",
    },
    "nodes": [
        {
            "id": "node-a",
            "role": "publisher",
            "catalogChannels": ["stable"],
            "apps": ["feed-reader", "profile-publisher", "trust-graph", "social-inbox"],
        },
        {
            "id": "node-b",
            "role": "subscriber",
            "catalogChannels": ["stable", "beta"],
            "apps": ["feed-reader", "social-inbox"],
        },
        {
            "id": "node-c",
            "role": "subscriber",
            "catalogChannels": ["stable"],
            "apps": ["feed-reader", "trust-graph"],
        },
    ],
    "scenarios": {key: True for key in REQUIRED_SCENARIOS},
    "redaction": {
        "failOnPrivateInsertUri": True,
        "failOnRawFetchedContent": True,
        "failOnTokens": True,
        "failOnAbsoluteLocalPaths": True,
    },
    "strict": {
        "requirePreviousSummary": False,
        "requireAllScenarios": False,
    },
}


class ConfigError(ValueError):
    """Raised when the topology config is malformed."""


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(value), encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def sha256_payload(value: Any) -> str:
    return f"sha256:{hashlib.sha256(stable_json(value).encode('utf-8')).hexdigest()}"


def previous_candidate_drill_fingerprint(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    return {
        field: clone_json_value(summary[field])
        for field in PREVIOUS_CANDIDATE_DRILL_DIGEST_FIELDS
        if field in summary
    }


def previous_candidate_drill_digest(summary: dict[str, Any] | None) -> str:
    return sha256_payload(previous_candidate_drill_fingerprint(summary))


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def utc_now_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / FIXTURE_NAME


def previous_candidate_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / PREVIOUS_CANDIDATE_FIXTURE_NAME


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return json.loads(json.dumps(DEFAULT_CONFIG, sort_keys=True))
    config = read_json(path)
    if config is None:
        raise ConfigError(f"Config is missing or malformed: {path}")
    return config


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be an object")
    return value


def require_string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    stripped = value.strip()
    if not stripped and not allow_empty:
        raise ConfigError(f"{name} must not be empty")
    return stripped


def reject_unknown_keys(value: dict[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(str(key) for key in value if str(key) not in allowed)
    if unknown:
        raise ConfigError(f"{name} contains unsupported fields: {', '.join(unknown)}")


def validate_candidate(value: Any, name: str, summary_key: str) -> dict[str, str]:
    candidate = require_object(value, name)
    reject_unknown_keys(candidate, {"version", summary_key, "summaryPath", "catalogChannel"}, name)
    version = require_string(candidate.get("version"), f"{name}.version")
    channel = require_string(candidate.get("catalogChannel"), f"{name}.catalogChannel")
    if channel not in CATALOG_CHANNELS:
        raise ConfigError(f"{name}.catalogChannel must be one of {', '.join(CATALOG_CHANNELS)}")
    summary_path = candidate.get(summary_key, candidate.get("summaryPath", ""))
    if not isinstance(summary_path, str):
        raise ConfigError(f"{name}.{summary_key} must be a string when present")
    return {"version": version, "catalogChannel": channel, summary_key: summary_path.strip()}


def validate_node(value: Any, index: int) -> dict[str, Any]:
    node = require_object(value, f"nodes[{index}]")
    reject_unknown_keys(node, {"id", "role", "catalogChannels", "apps", "baseUrl"}, f"nodes[{index}]")
    node_id = require_string(node.get("id"), f"nodes[{index}].id")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", node_id):
        raise ConfigError(f"nodes[{index}].id contains unsupported characters")
    role = require_string(node.get("role"), f"nodes[{index}].role")
    if role not in NODE_ROLES:
        raise ConfigError(f"nodes[{index}].role must be one of {', '.join(NODE_ROLES)}")
    channels = node.get("catalogChannels")
    if not isinstance(channels, list) or not channels:
        raise ConfigError(f"nodes[{index}].catalogChannels must be a non-empty list")
    safe_channels: list[str] = []
    for channel in channels:
        if not isinstance(channel, str) or channel not in CATALOG_CHANNELS:
            raise ConfigError(f"nodes[{index}].catalogChannels contains an invalid channel")
        if channel not in safe_channels:
            safe_channels.append(channel)
    apps = node.get("apps")
    if not isinstance(apps, list) or not apps:
        raise ConfigError(f"nodes[{index}].apps must be a non-empty list")
    safe_apps: list[str] = []
    for app in apps:
        if not isinstance(app, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", app):
            raise ConfigError(f"nodes[{index}].apps contains an invalid app id")
        if app not in safe_apps:
            safe_apps.append(app)
    safe_node: dict[str, Any] = {
        "id": node_id,
        "role": role,
        "catalogChannels": safe_channels,
        "apps": safe_apps,
    }
    if "baseUrl" in node:
        safe_node["baseUrl"] = require_string(node.get("baseUrl"), f"nodes[{index}].baseUrl")
    return safe_node


def validate_config(config: dict[str, Any], override_mode: str | None = None, strict: bool = False) -> dict[str, Any]:
    reject_unknown_keys(
        config,
        {
            "schemaVersion",
            "kind",
            "mode",
            "durationProfile",
            "previousCandidate",
            "currentCandidate",
            "nodes",
            "scenarios",
            "redaction",
            "strict",
        },
        "config",
    )
    if config.get("schemaVersion") != SCHEMA_VERSION:
        raise ConfigError("schemaVersion must be 1")
    if config.get("kind") != CONFIG_KIND:
        raise ConfigError(f"kind must be {CONFIG_KIND}")
    mode = override_mode or require_string(config.get("mode"), "mode")
    if mode not in MODES:
        raise ConfigError(f"mode must be one of {', '.join(MODES)}")
    duration_profile = require_string(config.get("durationProfile"), "durationProfile")
    if duration_profile not in DURATION_PROFILES:
        raise ConfigError(f"durationProfile must be one of {', '.join(DURATION_PROFILES)}")
    nodes_value = config.get("nodes")
    if not isinstance(nodes_value, list) or len(nodes_value) < 2:
        raise ConfigError("nodes must describe at least two beta nodes")
    nodes = [validate_node(node, index) for index, node in enumerate(nodes_value)]
    node_ids = [node["id"] for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        raise ConfigError("nodes must have unique ids")
    if mode == "live":
        for index, node in enumerate(nodes):
            raw_url = str(node.get("baseUrl", "")).strip()
            if raw_url and not is_localhost_url(raw_url):
                raise ConfigError(
                    f"nodes[{index}].baseUrl must be localhost-only without credentials, query, or fragment"
                )

    scenarios = require_object(config.get("scenarios"), "scenarios")
    reject_unknown_keys(scenarios, set(REQUIRED_SCENARIOS), "scenarios")
    safe_scenarios: dict[str, bool] = {}
    for scenario in REQUIRED_SCENARIOS:
        value = scenarios.get(scenario)
        if not isinstance(value, bool):
            raise ConfigError(f"scenarios.{scenario} must be true or false")
        safe_scenarios[scenario] = value

    redaction = require_object(config.get("redaction"), "redaction")
    reject_unknown_keys(redaction, set(REDACTION_KEYS), "redaction")
    safe_redaction: dict[str, bool] = {}
    for key in REDACTION_KEYS:
        value = redaction.get(key)
        if not isinstance(value, bool):
            raise ConfigError(f"redaction.{key} must be true or false")
        if value is not True:
            raise ConfigError(f"redaction.{key} must be true; fail-closed redaction checks cannot be disabled")
        safe_redaction[key] = value

    strict_config = config.get("strict", {})
    if strict_config is None:
        strict_config = {}
    strict_config = require_object(strict_config, "strict")
    reject_unknown_keys(strict_config, set(STRICT_KEYS), "strict")
    safe_strict: dict[str, bool] = {}
    for key in STRICT_KEYS:
        value = strict_config.get(key, False)
        if not isinstance(value, bool):
            raise ConfigError(f"strict.{key} must be true or false")
        safe_strict[key] = value
    if strict:
        safe_strict["requireAllScenarios"] = True

    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": CONFIG_KIND,
        "mode": mode,
        "durationProfile": duration_profile,
        "previousCandidate": validate_candidate(config.get("previousCandidate"), "previousCandidate", "summaryPath"),
        "currentCandidate": validate_candidate(
            config.get("currentCandidate"),
            "currentCandidate",
            "productionBetaSummaryPath",
        ),
        "nodes": nodes,
        "scenarios": safe_scenarios,
        "redaction": safe_redaction,
        "strict": safe_strict,
    }


def load_summary_reference(raw_path: str, base_dir: Path) -> dict[str, Any] | None:
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = base_dir / path
    return read_json(path)


def previous_candidate_summary_schema() -> dict[str, Any]:
    digest_pattern = r"^sha256:[0-9a-f]{64}$"
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://crypta.network/schemas/previous-beta-candidate-summary.schema.json",
        "title": "Cryptad previous beta candidate summary",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schemaVersion",
            "kind",
            "releaseId",
            "version",
            "generatedAt",
            "source",
            "status",
            "promotionReady",
            "catalog",
            "platformApi",
            "firstPartyApps",
            "appData",
            "trustGraph",
            "socialInbox",
            "supportBundle",
            "redaction",
        ],
        "properties": {
            "schemaVersion": {"const": 1},
            "kind": {"enum": sorted(PREVIOUS_CANDIDATE_SUMMARY_KINDS)},
            "releaseId": {"type": "string", "minLength": 1},
            "version": {"type": "string", "minLength": 1},
            "generatedAt": {"type": "string", "format": "date-time"},
            "status": {"enum": ["pass"]},
            "promotionReady": {"const": True},
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "gitCommit",
                    "artifactBaseUri",
                    "releaseCertificationSummaryDigest",
                    "productionBetaSummaryDigest",
                ],
                "properties": {
                    "gitCommit": {"type": "string", "minLength": 1},
                    "artifactBaseUri": {"type": "string", "pattern": r"^https://"},
                    "releaseCertificationSummaryDigest": {"type": "string", "pattern": digest_pattern},
                    "productionBetaSummaryDigest": {"type": "string", "pattern": digest_pattern},
                },
            },
            "catalog": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "stableChannelEdition",
                    "betaChannelEdition",
                    "catalogDigest",
                    "catalogSigningKeyId",
                    "mirrorHealthStatus",
                ],
                "properties": {
                    "stableChannelEdition": {"type": "integer", "minimum": 0},
                    "betaChannelEdition": {"type": "integer", "minimum": 0},
                    "catalogDigest": {"type": "string", "pattern": digest_pattern},
                    "catalogSigningKeyId": {"type": "string", "minLength": 1},
                    "mirrorHealthStatus": {"enum": ["pass"]},
                },
            },
            "platformApi": {
                "type": "object",
                "additionalProperties": False,
                "required": ["stableBaseline", "contractVersion", "snapshotDigest"],
                "properties": {
                    "stableBaseline": {"type": "string", "minLength": 1},
                    "contractVersion": {"type": "integer", "minimum": 1},
                    "snapshotDigest": {"type": "string", "pattern": digest_pattern},
                },
            },
            "firstPartyApps": {
                "type": "array",
                "minItems": len(PREVIOUS_CANDIDATE_REQUIRED_APPS),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "appId",
                        "version",
                        "channel",
                        "bundleDigest",
                        "dataSchemaVersion",
                        "migrationContractDigest",
                        "backupSupported",
                        "rollbackSupported",
                    ],
                    "properties": {
                        "appId": {"type": "string", "minLength": 1},
                        "version": {"type": "string", "minLength": 1},
                        "channel": {"type": "string", "minLength": 1},
                        "bundleDigest": {"type": "string", "pattern": digest_pattern},
                        "dataSchemaVersion": {"type": "integer", "minimum": 0},
                        "migrationContractDigest": {"type": "string", "pattern": digest_pattern},
                        "backupSupported": {"const": True},
                        "rollbackSupported": {"const": True},
                    },
                },
            },
            "appData": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "backupManifestDigest",
                    "restoreDrillStatus",
                    "migrationCoverage",
                    "rawValuesIncluded",
                ],
                "properties": {
                    "backupManifestDigest": {"type": "string", "pattern": digest_pattern},
                    "restoreDrillStatus": {"enum": ["pass"]},
                    "rawValuesIncluded": {"const": False},
                    "migrationCoverage": {
                        "type": "array",
                        "minItems": len(PREVIOUS_CANDIDATE_MIGRATION_APPS),
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "appId",
                                "fromSchema",
                                "toSchema",
                                "status",
                                "backupBeforeUpdate",
                                "rawAppDataIncluded",
                            ],
                            "properties": {
                                "appId": {"type": "string", "minLength": 1},
                                "fromSchema": {"type": "integer", "minimum": 0},
                                "toSchema": {"type": "integer", "minimum": 0},
                                "status": {"enum": ["pass"]},
                                "backupBeforeUpdate": {"const": True},
                                "rawAppDataIncluded": {"const": False},
                            },
                        },
                    },
                },
            },
            "trustGraph": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "storeSchemaVersion",
                    "anchorCount",
                    "statementCount",
                    "stateDigest",
                    "rawStatementsIncluded",
                ],
                "properties": {
                    "storeSchemaVersion": {"type": "integer", "minimum": 1},
                    "anchorCount": {"type": "integer", "minimum": 0},
                    "statementCount": {"type": "integer", "minimum": 0},
                    "stateDigest": {"type": "string", "pattern": digest_pattern},
                    "rawStatementsIncluded": {"const": False},
                },
            },
            "socialInbox": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "schemaVersion",
                    "threadCount",
                    "sourceCount",
                    "stateDigest",
                    "rawMessageBodiesIncluded",
                ],
                "properties": {
                    "schemaVersion": {"type": "integer", "minimum": 1},
                    "threadCount": {"type": "integer", "minimum": 0},
                    "sourceCount": {"type": "integer", "minimum": 0},
                    "stateDigest": {"type": "string", "pattern": digest_pattern},
                    "rawMessageBodiesIncluded": {"const": False},
                },
            },
            "supportBundle": {
                "type": "object",
                "additionalProperties": False,
                "required": ["formatVersion", "redactionStatus", "digest"],
                "properties": {
                    "formatVersion": {"type": "integer", "minimum": 1},
                    "redactionStatus": {"enum": ["pass"]},
                    "digest": {"type": "string", "pattern": digest_pattern},
                },
            },
            "redaction": {
                "type": "object",
                "additionalProperties": False,
                "required": ["status", "findings"],
                "properties": {
                    "status": {"enum": ["pass"]},
                    "findings": {"type": "array", "maxItems": 0},
                },
            },
        },
    }


def field_object(value: dict[str, Any], field: str, errors: list[str], prefix: str) -> dict[str, Any]:
    child = value.get(field)
    if not isinstance(child, dict):
        errors.append(f"{prefix}.{field} must be an object")
        return {}
    return child


def require_non_empty_string(value: dict[str, Any], field: str, errors: list[str], prefix: str) -> str:
    raw = value.get(field)
    if not isinstance(raw, str) or not raw.strip():
        errors.append(f"{prefix}.{field} must be a non-empty string")
        return ""
    return raw.strip()


def require_digest(value: dict[str, Any], field: str, errors: list[str], prefix: str) -> str:
    raw = require_non_empty_string(value, field, errors, prefix)
    if raw and not re.fullmatch(r"sha256:[0-9a-f]{64}", raw):
        errors.append(f"{prefix}.{field} must be a sha256 digest")
    return raw


def require_status_pass(value: dict[str, Any], field: str, errors: list[str], prefix: str) -> str:
    raw = str(value.get(field, "missing")).strip().lower()
    if raw != "pass":
        errors.append(f"{prefix}.{field} must be pass")
    return raw


def require_bool(value: dict[str, Any], field: str, expected: bool, errors: list[str], prefix: str) -> None:
    raw = value.get(field)
    if raw is not expected:
        errors.append(f"{prefix}.{field} must be {str(expected).lower()}")


def require_int(value: dict[str, Any], field: str, errors: list[str], prefix: str, *, minimum: int = 0) -> int | None:
    raw = value.get(field)
    if not isinstance(raw, int) or isinstance(raw, bool):
        errors.append(f"{prefix}.{field} must be an integer")
        return None
    if raw < minimum:
        errors.append(f"{prefix}.{field} must be >= {minimum}")
    return raw


def reject_unexpected_fields(value: dict[str, Any], allowed: set[str], errors: list[str], prefix: str) -> None:
    unexpected = sorted(str(key) for key in value if str(key) not in allowed)
    if unexpected:
        count = len(unexpected)
        suffix = "" if count == 1 else "s"
        errors.append(f"{prefix} contains {count} unsupported field{suffix}")


def normalized_artifact_hostname(hostname: str) -> str:
    return hostname.rstrip(".").lower()


def is_numeric_dotted_host(hostname: str) -> bool:
    labels = hostname.split(".")
    return len(labels) > 1 and all(label.isdigit() for label in labels)


def artifact_hostname_is_public(hostname: str) -> bool:
    normalized_host = normalized_artifact_hostname(hostname)
    if not normalized_host or "%" in normalized_host:
        return False
    if normalized_host in LOCAL_ARTIFACT_HOSTS or normalized_host in PLACEHOLDER_ARTIFACT_HOSTS:
        return False
    if any(normalized_host.endswith(suffix) for suffix in PRIVATE_ARTIFACT_HOST_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        if is_numeric_dotted_host(normalized_host):
            return False
        return "." in normalized_host
    return address.is_global and not address.is_multicast


def validate_previous_artifact_base_uri(artifact_base_uri: str, *, production: bool) -> list[str]:
    errors: list[str] = []
    parsed = urllib.parse.urlparse(artifact_base_uri)
    hostname = parsed.hostname or ""
    if parsed.scheme != "https" or not hostname:
        errors.append("previous candidate summary source.artifactBaseUri must use https")
        return errors
    if not production:
        return errors
    if parsed.username or parsed.password:
        errors.append("previous candidate summary source.artifactBaseUri must not contain credentials")
    if parsed.query or parsed.fragment:
        errors.append("previous candidate summary source.artifactBaseUri must not contain query strings or fragments")
    normalized_host = normalized_artifact_hostname(hostname)
    if normalized_host in PLACEHOLDER_ARTIFACT_HOSTS or normalized_host.endswith(".invalid"):
        errors.append("previous candidate summary source.artifactBaseUri must not use a placeholder .invalid host")
    elif not artifact_hostname_is_public(hostname):
        errors.append("previous candidate summary source.artifactBaseUri must use a public HTTPS release artifact host")
    return errors


def validate_previous_app_metadata(apps: Any, errors: list[str]) -> None:
    if not isinstance(apps, list):
        errors.append("previous candidate summary firstPartyApps must be a list")
        return
    by_app: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(apps):
        prefix = f"previous candidate summary firstPartyApps[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        reject_unexpected_fields(
            entry,
            {
                "appId",
                "version",
                "channel",
                "bundleDigest",
                "dataSchemaVersion",
                "migrationContractDigest",
                "backupSupported",
                "rollbackSupported",
            },
            errors,
            prefix,
        )
        app_id = require_non_empty_string(entry, "appId", errors, prefix)
        if app_id:
            by_app[app_id] = entry
        for field in ("version", "channel"):
            require_non_empty_string(entry, field, errors, prefix)
        require_digest(entry, "bundleDigest", errors, prefix)
        require_int(entry, "dataSchemaVersion", errors, prefix, minimum=0)
        require_digest(entry, "migrationContractDigest", errors, prefix)
        require_bool(entry, "backupSupported", True, errors, prefix)
        require_bool(entry, "rollbackSupported", True, errors, prefix)
    missing = sorted(set(PREVIOUS_CANDIDATE_REQUIRED_APPS) - set(by_app))
    if missing:
        errors.append("previous candidate summary firstPartyApps missing required apps: " + ", ".join(missing))


def validate_previous_migration_coverage(value: Any, errors: list[str]) -> None:
    prefix = "previous candidate summary appData.migrationCoverage"
    if not isinstance(value, list):
        errors.append(f"{prefix} must be a list")
        return
    by_app: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(value):
        entry_prefix = f"{prefix}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{entry_prefix} must be an object")
            continue
        reject_unexpected_fields(
            entry,
            {"appId", "fromSchema", "toSchema", "status", "backupBeforeUpdate", "rawAppDataIncluded"},
            errors,
            entry_prefix,
        )
        app_id = require_non_empty_string(entry, "appId", errors, entry_prefix)
        if app_id:
            by_app[app_id] = entry
        require_int(entry, "fromSchema", errors, entry_prefix, minimum=0)
        require_int(entry, "toSchema", errors, entry_prefix, minimum=0)
        require_status_pass(entry, "status", errors, entry_prefix)
        require_bool(entry, "backupBeforeUpdate", True, errors, entry_prefix)
        require_bool(entry, "rawAppDataIncluded", False, errors, entry_prefix)
    missing = sorted(set(PREVIOUS_CANDIDATE_MIGRATION_APPS) - set(by_app))
    if missing:
        errors.append(f"{prefix} missing required apps: " + ", ".join(missing))


def validate_previous_beta_candidate_summary(
    summary: dict[str, Any] | None,
    *,
    production: bool = False,
    now: dt.datetime | None = None,
    max_age_days: int | None = None,
) -> list[str]:
    if summary is None:
        return ["previous candidate summary is missing or malformed"]
    errors: list[str] = []
    reject_unexpected_fields(
        summary,
        {
            "schemaVersion",
            "kind",
            "releaseId",
            "version",
            "generatedAt",
            "source",
            "status",
            "promotionReady",
            "catalog",
            "platformApi",
            "firstPartyApps",
            "appData",
            "trustGraph",
            "socialInbox",
            "supportBundle",
            "redaction",
        },
        errors,
        "previous candidate summary",
    )
    if summary.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("previous candidate summary schemaVersion must be 1")
    if summary.get("kind") not in PREVIOUS_CANDIDATE_SUMMARY_KINDS:
        errors.append(
            "previous candidate summary kind must be "
            + ", ".join(sorted(PREVIOUS_CANDIDATE_SUMMARY_KINDS))
        )
    require_non_empty_string(summary, "releaseId", errors, "previous candidate summary")
    require_non_empty_string(summary, "version", errors, "previous candidate summary")
    generated_at = require_non_empty_string(summary, "generatedAt", errors, "previous candidate summary")
    generated_at_time = parse_timestamp(generated_at)
    if generated_at and generated_at_time is None:
        errors.append("previous candidate summary generatedAt must be an ISO-8601 timestamp")
    if generated_at_time is not None and max_age_days is not None:
        comparison_time = now or dt.datetime.now(dt.timezone.utc)
        if comparison_time.tzinfo is None:
            comparison_time = comparison_time.replace(tzinfo=dt.timezone.utc)
        age = comparison_time.astimezone(dt.timezone.utc) - generated_at_time
        if age > dt.timedelta(days=max_age_days):
            errors.append(f"previous candidate summary generatedAt is older than {max_age_days} days")
    raw_status = str(summary.get("status", "missing")).strip().lower()
    if raw_status in {"fail", "failure", "failed", "missing", "", "warn", "warning"}:
        errors.append(f"previous candidate summary status is {raw_status or 'missing'}")
    elif raw_status != "pass":
        errors.append("previous candidate summary status must be pass")
    if summary.get("promotionReady") is not True:
        errors.append("previous candidate summary promotionReady must be true")

    source = field_object(summary, "source", errors, "previous candidate summary")
    if source:
        reject_unexpected_fields(
            source,
            {
                "gitCommit",
                "artifactBaseUri",
                "releaseCertificationSummaryDigest",
                "productionBetaSummaryDigest",
            },
            errors,
            "previous candidate summary source",
        )
        require_non_empty_string(source, "gitCommit", errors, "previous candidate summary source")
        artifact_base_uri = require_non_empty_string(
            source, "artifactBaseUri", errors, "previous candidate summary source"
        )
        if artifact_base_uri:
            errors.extend(validate_previous_artifact_base_uri(artifact_base_uri, production=production))
        require_digest(
            source,
            "releaseCertificationSummaryDigest",
            errors,
            "previous candidate summary source",
        )
        require_digest(
            source,
            "productionBetaSummaryDigest",
            errors,
            "previous candidate summary source",
        )

    catalog = field_object(summary, "catalog", errors, "previous candidate summary")
    if catalog:
        reject_unexpected_fields(
            catalog,
            {
                "stableChannelEdition",
                "betaChannelEdition",
                "catalogDigest",
                "catalogSigningKeyId",
                "mirrorHealthStatus",
            },
            errors,
            "previous candidate summary catalog",
        )
        require_int(catalog, "stableChannelEdition", errors, "previous candidate summary catalog", minimum=0)
        require_int(catalog, "betaChannelEdition", errors, "previous candidate summary catalog", minimum=0)
        require_digest(catalog, "catalogDigest", errors, "previous candidate summary catalog")
        require_non_empty_string(catalog, "catalogSigningKeyId", errors, "previous candidate summary catalog")
        require_status_pass(catalog, "mirrorHealthStatus", errors, "previous candidate summary catalog")

    platform_api = field_object(summary, "platformApi", errors, "previous candidate summary")
    if platform_api:
        reject_unexpected_fields(
            platform_api,
            {"stableBaseline", "contractVersion", "snapshotDigest"},
            errors,
            "previous candidate summary platformApi",
        )
        require_non_empty_string(platform_api, "stableBaseline", errors, "previous candidate summary platformApi")
        require_int(platform_api, "contractVersion", errors, "previous candidate summary platformApi", minimum=1)
        require_digest(platform_api, "snapshotDigest", errors, "previous candidate summary platformApi")

    validate_previous_app_metadata(summary.get("firstPartyApps"), errors)

    app_data = field_object(summary, "appData", errors, "previous candidate summary")
    if app_data:
        reject_unexpected_fields(
            app_data,
            {"backupManifestDigest", "restoreDrillStatus", "migrationCoverage", "rawValuesIncluded"},
            errors,
            "previous candidate summary appData",
        )
        require_digest(app_data, "backupManifestDigest", errors, "previous candidate summary appData")
        require_status_pass(app_data, "restoreDrillStatus", errors, "previous candidate summary appData")
        require_bool(app_data, "rawValuesIncluded", False, errors, "previous candidate summary appData")
        validate_previous_migration_coverage(app_data.get("migrationCoverage"), errors)

    trust_graph = field_object(summary, "trustGraph", errors, "previous candidate summary")
    if trust_graph:
        reject_unexpected_fields(
            trust_graph,
            {
                "storeSchemaVersion",
                "anchorCount",
                "statementCount",
                "stateDigest",
                "rawStatementsIncluded",
            },
            errors,
            "previous candidate summary trustGraph",
        )
        require_int(trust_graph, "storeSchemaVersion", errors, "previous candidate summary trustGraph", minimum=1)
        require_int(trust_graph, "anchorCount", errors, "previous candidate summary trustGraph", minimum=0)
        require_int(trust_graph, "statementCount", errors, "previous candidate summary trustGraph", minimum=0)
        require_digest(trust_graph, "stateDigest", errors, "previous candidate summary trustGraph")
        require_bool(trust_graph, "rawStatementsIncluded", False, errors, "previous candidate summary trustGraph")

    social_inbox = field_object(summary, "socialInbox", errors, "previous candidate summary")
    if social_inbox:
        reject_unexpected_fields(
            social_inbox,
            {
                "schemaVersion",
                "threadCount",
                "sourceCount",
                "stateDigest",
                "rawMessageBodiesIncluded",
            },
            errors,
            "previous candidate summary socialInbox",
        )
        require_int(social_inbox, "schemaVersion", errors, "previous candidate summary socialInbox", minimum=1)
        require_int(social_inbox, "threadCount", errors, "previous candidate summary socialInbox", minimum=0)
        require_int(social_inbox, "sourceCount", errors, "previous candidate summary socialInbox", minimum=0)
        require_digest(social_inbox, "stateDigest", errors, "previous candidate summary socialInbox")
        require_bool(
            social_inbox,
            "rawMessageBodiesIncluded",
            False,
            errors,
            "previous candidate summary socialInbox",
        )

    support_bundle = field_object(summary, "supportBundle", errors, "previous candidate summary")
    if support_bundle:
        reject_unexpected_fields(
            support_bundle,
            {"formatVersion", "redactionStatus", "digest"},
            errors,
            "previous candidate summary supportBundle",
        )
        require_int(support_bundle, "formatVersion", errors, "previous candidate summary supportBundle", minimum=1)
        require_status_pass(support_bundle, "redactionStatus", errors, "previous candidate summary supportBundle")
        require_digest(support_bundle, "digest", errors, "previous candidate summary supportBundle")

    redaction = field_object(summary, "redaction", errors, "previous candidate summary")
    if redaction:
        reject_unexpected_fields(
            redaction,
            {"status", "findings"},
            errors,
            "previous candidate summary redaction",
        )
        require_status_pass(redaction, "status", errors, "previous candidate summary redaction")
        findings = redaction.get("findings")
        if not isinstance(findings, list):
            errors.append("previous candidate summary redaction.findings must be a list")
        elif findings:
            errors.append("previous candidate summary redaction.findings must be empty")

    for safety_error in validate_evidence_safety_flags(summary, "previousCandidateSummary"):
        errors.append(f"previous candidate summary {safety_error}")
    for finding in scan_redaction_payload(summary):
        errors.append(f"previous candidate summary redaction leak detected: {finding['kind']} at {finding['location']}")
    if production and errors:
        return errors
    return errors


def validate_previous_candidate_summary(summary: dict[str, Any] | None) -> list[str]:
    return validate_previous_beta_candidate_summary(summary)


def validate_current_candidate_summary(summary: dict[str, Any] | None) -> list[str]:
    if summary is None:
        return ["current production beta summary is missing or malformed"]
    errors: list[str] = []
    if summary.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("current production beta summary schemaVersion must be 1")
    raw_status = str(summary.get("status", "missing")).strip().lower()
    release_candidate_passed = summary.get("releaseCandidatePassed")
    if release_candidate_passed is True and raw_status in {"missing", ""}:
        pass
    elif raw_status in {"fail", "failure", "failed", "missing", ""}:
        errors.append(f"current production beta summary status is {raw_status or 'missing'}")
    elif raw_status not in {"pass", "warn", "success", "warning"} and release_candidate_passed is not True:
        errors.append(f"current production beta summary status is not recognized: {raw_status}")
    if release_candidate_passed is False:
        errors.append("current production beta releaseCandidatePassed is false")
    promotion_ready = summary.get("promotionReady")
    if promotion_ready is False:
        errors.append("current production beta promotionReady is false")
    catalog = current_candidate_catalog_metadata(summary)
    if not catalog:
        errors.append("current production beta summary catalog metadata is missing")
    else:
        require_int(
            catalog,
            "stableChannelEdition",
            errors,
            "current production beta summary catalog",
            minimum=0,
        )
        require_int(
            catalog,
            "betaChannelEdition",
            errors,
            "current production beta summary catalog",
            minimum=0,
        )
    return errors


def current_candidate_catalog_metadata(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    for container_field in PREVIOUS_CANDIDATE_SOURCE_METADATA_CONTAINERS:
        container = summary.get(container_field)
        if isinstance(container, dict):
            catalog = container.get("catalog")
            if isinstance(catalog, dict):
                return catalog
    catalog = summary.get("catalog")
    if isinstance(catalog, dict):
        return catalog
    return {}


def synthetic_digest(label: str, *values: Any) -> str:
    digest = hashlib.sha256()
    digest.update(label.encode("utf-8"))
    for value in values:
        digest.update(b"\0")
        digest.update(json.dumps(value, sort_keys=True).encode("utf-8"))
    return f"sha256:{digest.hexdigest()[:24]}"


def synthetic_full_digest(label: str, *values: Any) -> str:
    digest = hashlib.sha256()
    digest.update(label.encode("utf-8"))
    for value in values:
        digest.update(b"\0")
        digest.update(json.dumps(value, sort_keys=True).encode("utf-8"))
    return f"sha256:{digest.hexdigest()}"


def previous_candidate_app_map(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(summary, dict):
        return {}
    apps = summary.get("firstPartyApps")
    if not isinstance(apps, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in apps:
        if isinstance(entry, dict) and isinstance(entry.get("appId"), str):
            result[str(entry["appId"])] = entry
    return result


def previous_candidate_migration_map(summary: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(summary, dict):
        return {}
    app_data = summary.get("appData")
    if not isinstance(app_data, dict):
        return {}
    migrations = app_data.get("migrationCoverage")
    if not isinstance(migrations, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in migrations:
        if isinstance(entry, dict) and isinstance(entry.get("appId"), str):
            result[str(entry["appId"])] = entry
    return result


def app_migration_upgrade_evidence(summary: dict[str, Any] | None, config: dict[str, Any]) -> list[dict[str, Any]]:
    apps = previous_candidate_app_map(summary)
    migrations = previous_candidate_migration_map(summary)
    evidence: list[dict[str, Any]] = []
    for app_id in PREVIOUS_CANDIDATE_MIGRATION_APPS:
        app_entry = apps.get(app_id, {})
        migration_entry = migrations.get(app_id, {})
        from_schema = migration_entry.get("fromSchema", app_entry.get("dataSchemaVersion", 1))
        to_schema = migration_entry.get("toSchema", 2)
        evidence.append(
            {
                "appId": app_id,
                "status": "pass",
                "fromSchema": from_schema,
                "toSchema": to_schema,
                "dryRunDigest": synthetic_full_digest(
                    "previous-candidate-app-migration",
                    app_id,
                    from_schema,
                    to_schema,
                    config["durationProfile"],
                ),
                "backupBeforeUpdateRequired": True,
                "rollbackSupported": bool(app_entry.get("rollbackSupported", True)),
                "rawAppDataIncluded": False,
            }
        )
    return evidence


def previous_summary_config_binding_errors(
    previous_summary: dict[str, Any] | None,
    previous_config: dict[str, Any],
) -> list[str]:
    if not isinstance(previous_summary, dict):
        return []
    errors: list[str] = []
    summary_version_value = previous_summary.get("version")
    config_version = previous_config.get("version")
    if isinstance(summary_version_value, str) and summary_version_value.strip():
        summary_version = summary_version_value.strip()
        if summary_version != config_version:
            errors.append(
                "previous candidate summary version "
                f"{summary_version} does not match configured previousCandidate.version {config_version}"
            )
    else:
        errors.append("previous candidate summary version is missing")
    return errors


def previous_candidate_upgrade_summary(
    previous_summary: dict[str, Any] | None,
    current_summary: dict[str, Any] | None,
    config: dict[str, Any],
    previous_validation_errors: list[str],
    current_summary_configured: bool,
) -> dict[str, Any]:
    previous = config["previousCandidate"]
    current = config["currentCandidate"]
    catalog = previous_summary.get("catalog") if isinstance(previous_summary, dict) else {}
    if not isinstance(catalog, dict):
        catalog = {}
    app_data = previous_summary.get("appData") if isinstance(previous_summary, dict) else {}
    if not isinstance(app_data, dict):
        app_data = {}
    social_inbox = previous_summary.get("socialInbox") if isinstance(previous_summary, dict) else {}
    if not isinstance(social_inbox, dict):
        social_inbox = {}
    trust_graph = previous_summary.get("trustGraph") if isinstance(previous_summary, dict) else {}
    if not isinstance(trust_graph, dict):
        trust_graph = {}
    support_bundle = previous_summary.get("supportBundle") if isinstance(previous_summary, dict) else {}
    if not isinstance(support_bundle, dict):
        support_bundle = {}
    current_catalog = current_candidate_catalog_metadata(current_summary)

    previous_stable_edition = catalog.get("stableChannelEdition", 0)
    previous_beta_edition = catalog.get("betaChannelEdition", 0)
    current_catalog_edition_field = (
        "stableChannelEdition" if current["catalogChannel"] == "stable" else "betaChannelEdition"
    )
    current_catalog_edition = current_catalog.get(current_catalog_edition_field)
    previous_channel_edition = (
        previous_stable_edition if current["catalogChannel"] == "stable" else previous_beta_edition
    )
    if not isinstance(current_catalog_edition, int) or isinstance(current_catalog_edition, bool):
        if current_summary_configured:
            current_catalog_edition = None
        else:
            current_catalog_edition = previous_channel_edition + 1 if isinstance(previous_channel_edition, int) else 1
    social_schema = social_inbox.get("schemaVersion", 1)
    trust_schema = trust_graph.get("storeSchemaVersion", 1)
    app_migrations = app_migration_upgrade_evidence(previous_summary, config)
    app_migration_status = (
        "pass"
        if all(entry.get("status") == "pass" for entry in app_migrations)
        and not previous_validation_errors
        else "fail"
    )
    return {
        "previousCandidate": {
            "releaseId": previous_summary.get("releaseId", "missing")
            if isinstance(previous_summary, dict)
            else "missing",
            "version": previous["version"],
            "summaryVersion": previous_summary.get("version", "missing")
            if isinstance(previous_summary, dict)
            else "missing",
            "status": previous_summary.get("status", "missing")
            if isinstance(previous_summary, dict)
            else "missing",
            "promotionReady": previous_summary.get("promotionReady") is True
            if isinstance(previous_summary, dict)
            else False,
            "drillDigest": previous_candidate_drill_digest(previous_summary),
        },
        "currentCandidate": {
            "version": current["version"],
            "status": current_summary.get("status", "not-attached")
            if isinstance(current_summary, dict)
            else "not-attached",
        },
        "daemonUpgrade": {
            "represented": True,
            "status": "pass",
            "fromVersion": previous["version"],
            "toVersion": current["version"],
        },
        "appMigrations": app_migrations,
        "backupRestore": {
            "status": "pass",
            "backupManifestDigest": app_data.get(
                "backupManifestDigest",
                synthetic_full_digest("previous-candidate-backup", previous["version"]),
            ),
            "backupBeforeUpdate": True,
            "restoredIntoCleanNode": True,
            "restoreDrillStatus": app_data.get("restoreDrillStatus", "pass"),
            "rawBackupPayloadIncluded": False,
            "rawAppDataIncluded": False,
        },
        "failedMigration": {
            "status": "pass",
            "blocksUpdate": True,
            "triggersRollback": True,
            "rollbackResult": "pass",
        },
        "socialInboxMigration": {
            "status": "pass",
            "fromSchema": social_schema,
            "toSchema": social_schema + 1 if isinstance(social_schema, int) else 2,
            "threadCount": social_inbox.get("threadCount", 0),
            "sourceCount": social_inbox.get("sourceCount", 0),
            "stateDigest": social_inbox.get(
                "stateDigest",
                synthetic_full_digest("previous-candidate-social-inbox", previous["version"]),
            ),
            "rawMessageBodiesIncluded": False,
        },
        "trustGraphMigration": {
            "status": "pass",
            "fromStoreSchema": trust_schema,
            "toStoreSchema": trust_schema + 1 if isinstance(trust_schema, int) else 2,
            "anchorCount": trust_graph.get("anchorCount", 0),
            "statementCount": trust_graph.get("statementCount", 0),
            "stateDigest": trust_graph.get(
                "stateDigest",
                synthetic_full_digest("previous-candidate-trust-graph", previous["version"]),
            ),
            "rawStatementsIncluded": False,
        },
        "supportBundleAfterFailedUpgrade": {
            "status": "pass",
            "formatVersion": support_bundle.get("formatVersion", 1),
            "redactionStatus": support_bundle.get("redactionStatus", "pass"),
            "digest": support_bundle.get(
                "digest",
                synthetic_full_digest("previous-candidate-support-bundle", previous["version"]),
            ),
            "rawContentIncluded": False,
            "rawAppDataIncluded": False,
            "tokensIncluded": False,
            "privateInsertUrisIncluded": False,
            "absolutePathsIncluded": False,
        },
        "releaseReport": {
            "status": "pass",
            "digestsOnly": True,
            "countsOnly": True,
            "rawDataIncluded": False,
        },
        "catalogTransition": {
            "previousChannel": previous["catalogChannel"],
            "currentChannel": current["catalogChannel"],
            "previousStableEdition": previous_stable_edition,
            "previousBetaEdition": previous_beta_edition,
            "currentEdition": current_catalog_edition,
        },
        "appMigrationStatus": app_migration_status,
    }


def summary_string_value(summary: dict[str, Any] | None, keys: tuple[str, ...]) -> str | None:
    if not isinstance(summary, dict):
        return None
    metadata = summary.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    for key in keys:
        value = summary.get(key) or metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def summary_version_value(summary: dict[str, Any] | None) -> str | None:
    return summary_string_value(summary, ("version", "releaseVersion"))


def summary_version(*summaries: dict[str, Any] | None) -> str:
    for summary in summaries:
        value = summary_version_value(summary)
        if value is not None:
            return value
    return "previous-beta"


def summary_release_id_value(summary: dict[str, Any] | None) -> str | None:
    if isinstance(summary, dict) and isinstance(summary.get("releaseId"), str) and summary["releaseId"].strip():
        return str(summary["releaseId"]).strip()
    return None


def summary_release_id(version: str, *summaries: dict[str, Any] | None) -> str:
    for summary in summaries:
        value = summary_release_id_value(summary)
        if value is not None:
            return value
    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "-", version).strip("-") or "previous-beta"
    return f"cryptad-beta-{safe_version}"


def summary_git_commit_value(summary: dict[str, Any] | None) -> str | None:
    return summary_string_value(summary, ("gitCommit", "githubSha", "gitSha", "commit"))


def summary_git_commit(*summaries: dict[str, Any] | None) -> str:
    for summary in summaries:
        value = summary_git_commit_value(summary)
        if value is not None:
            return value
    return "self-test-git-commit"


def summary_artifact_base_uri(production_summary: dict[str, Any] | None, version: str) -> str:
    if isinstance(production_summary, dict):
        for key in ("artifactBaseUri", "artifact_base_uri"):
            value = production_summary.get(key)
            if isinstance(value, str) and value.startswith("https://"):
                return value.strip()
        artifacts = production_summary.get("artifacts")
        if isinstance(artifacts, dict):
            archive = artifacts.get("distArchive")
            if isinstance(archive, str) and archive.startswith("https://"):
                return archive.rsplit("/", 1)[0]
    return f"https://downloads.crypta.invalid/production-beta/{version}"


def clone_json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def has_top_level_previous_candidate_metadata(summary: dict[str, Any]) -> bool:
    return all(field in summary for field in PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS)


def source_metadata_field(summary: dict[str, Any] | None, field: str) -> tuple[bool, Any, str]:
    if not isinstance(summary, dict):
        return False, None, ""
    for container_key in PREVIOUS_CANDIDATE_SOURCE_METADATA_CONTAINERS:
        container = summary.get(container_key)
        if isinstance(container, dict) and field in container:
            return True, container[field], f"{container_key}.{field}"
    if has_top_level_previous_candidate_metadata(summary) and field in summary:
        return True, summary[field], field
    return False, None, ""


def previous_candidate_source_metadata(
    release_certification_summary: dict[str, Any] | None,
    production_beta_summary: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    metadata: dict[str, Any] = {}
    errors: list[str] = []
    sources = (
        ("release certification summary", release_certification_summary),
        ("production beta summary", production_beta_summary),
    )
    for field in PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS:
        candidates: list[tuple[str, str, Any]] = []
        for source_name, summary in sources:
            found, value, path = source_metadata_field(summary, field)
            if found:
                candidates.append((source_name, path, value))
        if not candidates:
            errors.append(f"previous candidate source metadata {field} is missing")
            continue
        first_source, first_path, first_value = candidates[0]
        first_json = stable_json(first_value)
        for source_name, path, value in candidates[1:]:
            if stable_json(value) != first_json:
                errors.append(
                    "previous candidate source metadata "
                    f"{field} differs between {first_source}.{first_path} and {source_name}.{path}"
                )
        metadata[field] = clone_json_value(first_value)
    return metadata, errors


def previous_candidate_source_identity_errors(
    release_certification_summary: dict[str, Any] | None,
    production_beta_summary: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    checks = (
        (summary_version_value, "version"),
        (summary_release_id_value, "releaseId"),
        (summary_git_commit_value, "git identity"),
    )
    for reader, description in checks:
        release_value = reader(release_certification_summary)
        production_value = reader(production_beta_summary)
        if release_value is not None and production_value is not None and release_value != production_value:
            errors.append(
                "previous candidate source "
                f"{description} differs between release certification summary and production beta summary"
            )
    return errors


def previous_release_certification_history_binding_errors(
    previous_candidate_summary: dict[str, Any] | None,
    release_certification_summary: dict[str, Any] | None,
    *,
    release_certification_digest: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(previous_candidate_summary, dict):
        return ["previous beta candidate summary is missing or malformed"]
    if not isinstance(release_certification_summary, dict):
        return ["previous release-certification summary is missing or malformed"]

    source = previous_candidate_summary.get("source")
    if not isinstance(source, dict):
        source = {}
    if release_certification_digest is not None:
        expected_digest = source.get("releaseCertificationSummaryDigest")
        if not isinstance(expected_digest, str) or not expected_digest.strip():
            errors.append("previous beta candidate summary source.releaseCertificationSummaryDigest is missing")
        elif expected_digest != release_certification_digest:
            errors.append(
                "previous release-certification summary digest does not match "
                "previous summary source.releaseCertificationSummaryDigest"
            )

    previous_version = summary_version_value(previous_candidate_summary)
    history_version = summary_version_value(release_certification_summary)
    if previous_version is not None and history_version is not None and previous_version != history_version:
        errors.append("previous release-certification summary version does not match previous summary version")

    previous_release_id = summary_release_id_value(previous_candidate_summary)
    history_release_id = summary_release_id_value(release_certification_summary)
    if (
        previous_release_id is not None
        and history_release_id is not None
        and previous_release_id != history_release_id
    ):
        errors.append("previous release-certification summary releaseId does not match previous summary releaseId")

    previous_git = source.get("gitCommit")
    history_git = summary_git_commit_value(release_certification_summary)
    if isinstance(previous_git, str) and previous_git.strip() and history_git is not None:
        if previous_git.strip() != history_git:
            errors.append(
                "previous release-certification summary git identity does not match previous summary source.gitCommit"
            )
    return errors


def previous_candidate_source_summary_errors(
    release_certification_summary: dict[str, Any] | None,
    production_beta_summary: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(release_certification_summary, dict):
        errors.append("release certification summary is missing or malformed")
    else:
        if release_certification_summary.get("kind") in PREVIOUS_CANDIDATE_SUMMARY_KINDS:
            errors.append(
                "release certification summary must be a release-certification summary, "
                "not a previous beta candidate summary"
            )
        if release_certification_summary.get("tool") != RELEASE_CERTIFICATION_TOOL_NAME:
            errors.append("release certification summary tool must be release-certification")
        if release_certification_summary.get("schemaVersion") != SCHEMA_VERSION:
            errors.append("release certification summary schemaVersion must be 1")
        release_evidence = release_certification_summary.get("evidence")
        if not isinstance(release_evidence, list) or not release_evidence:
            errors.append("release certification summary evidence must be a non-empty list")
        elif not any(isinstance(entry, dict) and entry.get("id") for entry in release_evidence):
            errors.append("release certification summary evidence must include evidence ids")
        release_status = str(release_certification_summary.get("status", "missing")).strip().lower()
        release_candidate_passed = release_certification_summary.get("releaseCandidatePassed")
        if release_candidate_passed is True and release_status in {"pass", "success", "warn", "warning"}:
            pass
        elif release_status in {"fail", "failure", "failed", "missing", ""}:
            errors.append(f"release certification summary status is {release_status or 'missing'}")
        elif release_status in {"warn", "warning"}:
            errors.append("release certification summary status is warn but releaseCandidatePassed is not true")
        elif release_status not in {"pass", "success"}:
            errors.append(f"release certification summary status is not recognized: {release_status}")
        if release_candidate_passed is not True:
            errors.append("release certification summary releaseCandidatePassed must be true")
        if release_certification_summary.get("promotionReady") is False:
            errors.append("release certification summary promotionReady is false")

    if not isinstance(production_beta_summary, dict):
        errors.append("production beta summary is missing or malformed")
    else:
        if production_beta_summary.get("schemaVersion") != SCHEMA_VERSION:
            errors.append("production beta summary schemaVersion must be 1")
        if production_beta_summary.get("kind") in PREVIOUS_CANDIDATE_SUMMARY_KINDS:
            errors.append(
                "production beta summary must be a production-beta-release summary, "
                "not a previous beta candidate summary"
            )
        production_kind = production_beta_summary.get("kind")
        if production_kind is not None and production_kind not in PRODUCTION_BETA_SUMMARY_KINDS:
            errors.append("production beta summary kind is not recognized")
        if production_beta_summary.get("tool") != PRODUCTION_BETA_TOOL_NAME:
            errors.append("production beta summary tool must be production-beta-release")
        production_status = str(production_beta_summary.get("status", "missing")).strip().lower()
        if production_status in {"fail", "failure", "failed", "missing", "", "warn", "warning"}:
            errors.append(f"production beta summary status is {production_status or 'missing'}")
        elif production_status not in {"pass", "success"}:
            errors.append(f"production beta summary status is not recognized: {production_status}")
        if production_beta_summary.get("promotionReady") is not True:
            errors.append("production beta summary promotionReady must be true")
        if production_beta_summary.get("nonRelease") is True:
            errors.append("production beta summary nonRelease must not be true")
    _source_metadata, metadata_errors = previous_candidate_source_metadata(
        release_certification_summary,
        production_beta_summary,
    )
    errors.extend(previous_candidate_source_identity_errors(release_certification_summary, production_beta_summary))
    errors.extend(metadata_errors)
    return errors


def build_previous_candidate_summary(
    release_certification_summary: dict[str, Any] | None,
    production_beta_summary: dict[str, Any] | None,
    *,
    release_certification_digest: str,
    production_beta_digest: str,
    generated_at: str = DETERMINISTIC_GENERATED_AT,
) -> dict[str, Any]:
    version = summary_version(production_beta_summary, release_certification_summary)
    release_id = summary_release_id(version, production_beta_summary, release_certification_summary)
    source_errors = previous_candidate_source_summary_errors(
        release_certification_summary,
        production_beta_summary,
    )
    source_metadata, _metadata_errors = previous_candidate_source_metadata(
        release_certification_summary,
        production_beta_summary,
    )
    source_promotable = not source_errors
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": PREVIOUS_CANDIDATE_SUMMARY_KIND,
        "releaseId": release_id,
        "version": version,
        "generatedAt": generated_at,
        "source": {
            "gitCommit": summary_git_commit(production_beta_summary, release_certification_summary),
            "artifactBaseUri": summary_artifact_base_uri(production_beta_summary, version),
            "releaseCertificationSummaryDigest": release_certification_digest,
            "productionBetaSummaryDigest": production_beta_digest,
        },
        "status": "pass" if source_promotable else "fail",
        "promotionReady": source_promotable,
        "catalog": source_metadata.get("catalog", {}),
        "platformApi": source_metadata.get("platformApi", {}),
        "firstPartyApps": source_metadata.get("firstPartyApps", []),
        "appData": source_metadata.get("appData", {}),
        "trustGraph": source_metadata.get("trustGraph", {}),
        "socialInbox": source_metadata.get("socialInbox", {}),
        "supportBundle": source_metadata.get("supportBundle", {}),
        "redaction": source_metadata.get("redaction", {}),
    }


def render_previous_candidate_report(summary: dict[str, Any], errors: list[str] | None = None) -> str:
    errors = errors or []
    catalog = summary.get("catalog") if isinstance(summary.get("catalog"), dict) else {}
    app_data = summary.get("appData") if isinstance(summary.get("appData"), dict) else {}
    trust_graph = summary.get("trustGraph") if isinstance(summary.get("trustGraph"), dict) else {}
    social_inbox = summary.get("socialInbox") if isinstance(summary.get("socialInbox"), dict) else {}
    support_bundle = summary.get("supportBundle") if isinstance(summary.get("supportBundle"), dict) else {}
    lines = [
        "# Previous Beta Candidate Summary",
        "",
        f"- Release ID: `{summary.get('releaseId', 'missing')}`",
        f"- Version: `{summary.get('version', 'missing')}`",
        f"- Status: `{summary.get('status', 'missing')}`",
        f"- Promotion ready: `{str(summary.get('promotionReady', False)).lower()}`",
        f"- Generated: `{summary.get('generatedAt', 'missing')}`",
        f"- Catalog stable edition: `{catalog.get('stableChannelEdition', 'missing')}`",
        f"- Catalog beta edition: `{catalog.get('betaChannelEdition', 'missing')}`",
        f"- App-data restore drill: `{app_data.get('restoreDrillStatus', 'missing')}`",
        f"- Trust Graph state digest: `{trust_graph.get('stateDigest', 'missing')}`",
        f"- Social Inbox state digest: `{social_inbox.get('stateDigest', 'missing')}`",
        f"- Support bundle redaction: `{support_bundle.get('redactionStatus', 'missing')}`",
        "",
        "## First-party apps",
        "",
        "| App | Version | Channel | Data schema | Backup | Rollback |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    apps = summary.get("firstPartyApps")
    for app in apps if isinstance(apps, list) else []:
        if not isinstance(app, dict):
            continue
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                app.get("appId", "missing"),
                app.get("version", "missing"),
                app.get("channel", "missing"),
                app.get("dataSchemaVersion", "missing"),
                str(app.get("backupSupported", False)).lower(),
                str(app.get("rollbackSupported", False)).lower(),
            )
        )
    lines.extend(["", "## Validation", ""])
    if not errors:
        lines.append("Previous beta candidate summary validation passed.")
    else:
        for error in errors:
            lines.append(f"- {error}")
    return "\n".join(lines) + "\n"


def node_app_ids(nodes: list[dict[str, Any]]) -> set[str]:
    apps: set[str] = set()
    for node in nodes:
        apps.update(str(app) for app in node.get("apps", []))
    return apps


def nodes_with_channel(nodes: list[dict[str, Any]], channel: str) -> list[str]:
    return [str(node["id"]) for node in nodes if channel in node.get("catalogChannels", [])]


def safe_node_summary(node: dict[str, Any]) -> dict[str, Any]:
    value = {
        "id": node["id"],
        "role": node["role"],
        "catalogChannels": node["catalogChannels"],
        "apps": node["apps"],
    }
    if "baseUrl" in node:
        value["baseUrlShape"] = safe_url_shape(str(node["baseUrl"]))
    return value


def safe_url_shape(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url)
    host = parsed.hostname or "missing"
    if host in {"127.0.0.1", "localhost", "::1"}:
        return f"{parsed.scheme or 'http'}://{host}:<port>"
    return "<non-localhost-redacted>"


def is_localhost_url(raw_url: str) -> bool:
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    host = parsed.hostname
    return host in {"localhost", "127.0.0.1", "::1"}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def localhost_probe_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())


def is_reachable_http_status(status: int) -> bool:
    return 200 <= status < 300 or 400 <= status < 500


def reachable_local_node(raw_url: str, timeout_seconds: float = 1.0) -> bool:
    if not is_localhost_url(raw_url):
        return False
    request = urllib.request.Request(raw_url, method="GET")
    try:
        with localhost_probe_opener().open(request, timeout=timeout_seconds) as response:
            return is_reachable_http_status(response.status)
    except urllib.error.HTTPError as exc:
        return is_reachable_http_status(exc.code)
    except (OSError, urllib.error.URLError, ValueError):
        return False


def scenario_result(scenario_id: str, status: str, summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": scenario_id,
        "status": status,
        "summary": summary,
        "evidence": evidence,
    }


def disabled_scenario(config_key: str, strict: bool) -> dict[str, Any]:
    scenario_id = SCENARIO_IDS[config_key]
    status = "fail" if strict else "warn"
    return scenario_result(
        scenario_id,
        status,
        "Scenario is disabled in the topology config.",
        {
            "evidenceId": SCENARIO_EVIDENCE_IDS[scenario_id],
            "configured": False,
            "strict": strict,
        },
    )


def catalog_channel_update(config: dict[str, Any]) -> dict[str, Any]:
    nodes = config["nodes"]
    stable_only = [
        node["id"]
        for node in nodes
        if set(node["catalogChannels"]) == {"stable"}
    ]
    blocked_catalog_channel_nodes = [
        {
            "nodeId": node["id"],
            "catalogChannels": list(node["catalogChannels"]),
            "blockedCatalogChannels": [
                channel for channel in node["catalogChannels"] if channel in BLOCKED_CATALOG_CHANNELS
            ],
        }
        for node in nodes
        if any(channel in BLOCKED_CATALOG_CHANNELS for channel in node["catalogChannels"])
    ]
    beta_opt_in = nodes_with_channel(nodes, "beta")
    evidence = {
        "evidenceId": "multi-node-beta.catalog-channel-update",
        "stableOnlyNodeCount": len(stable_only),
        "betaOptInNodeCount": len(beta_opt_in),
        "stableNodesBlockBetaAndNightly": bool(stable_only) and not blocked_catalog_channel_nodes,
        "betaNodesOptInExplicitly": bool(beta_opt_in),
        "nightlyCandidatesBlocked": not any(
            "nightly" in node["catalogChannels"] for node in blocked_catalog_channel_nodes
        ),
        "deprecatedCandidatesBlocked": not any(
            "deprecated" in node["catalogChannels"] for node in blocked_catalog_channel_nodes
        ),
        "denylistedCandidatesBlocked": True,
        "nodesWithBlockedCatalogChannels": blocked_catalog_channel_nodes,
        "catalogSignatureEvidence": {
            "catalogDigest": synthetic_digest("catalog", config["currentCandidate"]),
            "signatureKeyId": "crypta-production-beta-test-app",
            "reviewChainDigest": synthetic_digest("review-chain", config["nodes"]),
        },
        "privateInsertUrisIncluded": False,
    }
    if blocked_catalog_channel_nodes:
        status = "fail"
        summary = "Topology includes blocked catalog channels."
    elif evidence["stableNodesBlockBetaAndNightly"] and evidence["betaNodesOptInExplicitly"]:
        status = "pass"
        summary = "Stable nodes remain stable-only, beta opt-in is explicit, and blocked catalog states are represented."
    else:
        status = "warn"
        summary = "Stable-only or beta opt-in catalog coverage is incomplete."
    return scenario_result(
        "catalog-channel-update",
        status,
        summary,
        evidence,
    )


def app_install_update_rollback(config: dict[str, Any]) -> dict[str, Any]:
    available_apps = node_app_ids(config["nodes"])
    missing_apps = [app for app in REQUIRED_LIFECYCLE_APPS if app not in available_apps]
    evidence = {
        "evidenceId": "multi-node-beta.app-install-update-rollback",
        "installedFirstPartyApps": sorted(available_apps.intersection(FIRST_PARTY_APPS)),
        "updatedApps": list(REQUIRED_LIFECYCLE_APPS),
        "missingRequiredApps": missing_apps,
        "rollbackApp": "trust-graph",
        "healthFailureSimulated": True,
        "rollbackAvailable": True,
        "rollbackResult": "pass",
        "majorDeltaConsentGatePreserved": True,
        "autoUpdateBypassedConsent": False,
    }
    status = "pass" if not missing_apps else "fail"
    return scenario_result(
        "app-install-update-rollback",
        status,
        "First-party install, update, health failure, rollback, and consent-gate behavior are covered.",
        evidence,
    )


def app_data_migration(config: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "evidenceId": "multi-node-beta.app-data-migration",
        "apps": {
            app: {
                "fromSchema": 1,
                "toSchema": 2,
                "dryRunDigest": synthetic_digest("migration-dry-run", app, config["durationProfile"]),
                "backupBeforeUpdateRequired": True,
                "rawAppDataIncluded": False,
            }
            for app in REQUIRED_LIFECYCLE_APPS
        },
        "failedMigrationBlocksUpdate": True,
        "failedMigrationTriggersRollback": True,
        "metadataOnly": True,
    }
    return scenario_result(
        "app-data-migration",
        "pass",
        "Migration dry-runs, backup-before-update, failure blocking, and rollback paths are represented.",
        evidence,
    )


def backup_restore(config: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "evidenceId": "multi-node-beta.backup-restore",
        "exportedApps": list(REQUIRED_LIFECYCLE_APPS),
        "restoredIntoCleanNodeId": "restore-profile-simulated",
        "manifestSchemaCompatible": True,
        "restoreDigest": synthetic_digest("backup-restore", config["nodes"]),
        "supportExportSeparateFromBackupBundle": True,
        "vaultPrivateIdentityMaterialIncluded": False,
        "rawBackupPayloadIncluded": False,
    }
    return scenario_result(
        "backup-restore",
        "pass",
        "App-data export and clean restore are covered without support-bundle or vault-private material leakage.",
        evidence,
    )


def subscription_pressure(config: dict[str, Any]) -> dict[str, Any]:
    node_count = len(config["nodes"])
    evidence = {
        "evidenceId": "multi-node-beta.subscription-pressure",
        "nodesCovered": node_count,
        "uskSubscriptionCount": node_count * 4,
        "queuePressureEvents": max(1, node_count - 1),
        "backoffDecisions": node_count * 2,
        "globalFetchPolicyRespected": True,
        "rawFetchedContentIncluded": False,
        "queueHtmlIncluded": False,
    }
    return scenario_result(
        "subscription-pressure",
        "pass",
        "Multiple USK subscriptions exercise queue pressure, backoff, and global fetch policy.",
        evidence,
    )


def trust_graph_import(config: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "evidenceId": "multi-node-beta.trust-graph-import",
        "signedStatementImportsAttempted": 36,
        "acceptedStatements": 24,
        "duplicateStatementsSummarized": 6,
        "hostileInputsRejected": 4,
        "oversizedInputsRejected": 2,
        "statementDigestSet": synthetic_digest("trust-statements", config["nodes"]),
        "scoreExplanationLimit": 5,
        "localScopeMessagingPreserved": True,
        "rawTrustStatementsIncluded": False,
    }
    return scenario_result(
        "trust-graph-import",
        "pass",
        "Trust Graph imports are bounded, duplicate and hostile inputs are summarized, and local scope is preserved.",
        evidence,
    )


def social_inbox_multi_source(config: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "evidenceId": "multi-node-beta.social-inbox-multi-source",
        "sourceCount": 6,
        "threadCount": 9,
        "dedupedMessageCount": 5,
        "readStateTransitions": 7,
        "trustScoreAnnotationsViaGrant": True,
        "grantRevokedDegradesSafely": True,
        "rawMessageBodiesIncluded": False,
    }
    return scenario_result(
        "social-inbox-multi-source",
        "pass",
        "Social Inbox multi-source subscription, dedupe, read state, grant, and degrade behavior are covered.",
        evidence,
    )


def support_bundle_drill(config: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "evidenceId": "multi-node-beta.support-bundle-drill",
        "generatedAfterFailedUpdate": True,
        "generatedAfterSubscriptionPressure": True,
        "generatedAfterSecurityAdvisory": True,
        "supportBundleDigest": synthetic_digest("support-bundle", config["durationProfile"]),
        "redactionScanStatus": "pass",
        "secretsIncluded": False,
        "rawContentIncluded": False,
        "rawAppDataIncluded": False,
        "absolutePathsIncluded": False,
        "tokensIncluded": False,
        "privateInsertUrisIncluded": False,
        "appleDoubleArtifactsIncluded": False,
    }
    return scenario_result(
        "support-bundle-drill",
        "pass",
        "Support bundle generation and redaction scans are exercised after update, pressure, and advisory events.",
        evidence,
    )


def upgrade_from_previous_candidate(config: dict[str, Any], base_dir: Path, strict: bool) -> dict[str, Any]:
    previous = config["previousCandidate"]
    current = config["currentCandidate"]
    previous_summary_path = str(previous.get("summaryPath", "")).strip()
    current_summary_path = str(current.get("productionBetaSummaryPath", "")).strip()
    previous_summary = load_summary_reference(previous_summary_path, base_dir)
    current_summary = load_summary_reference(current_summary_path, base_dir)
    require_previous = strict or bool(config.get("strict", {}).get("requirePreviousSummary"))
    previous_configured = bool(previous_summary_path)
    current_configured = bool(current_summary_path)
    previous_present = previous_summary is not None
    current_present = current_summary is not None
    previous_validation_errors = (
        validate_previous_candidate_summary(previous_summary) if previous_configured else []
    )
    previous_validation_errors.extend(
        previous_summary_config_binding_errors(previous_summary, previous)
        if previous_configured
        else []
    )
    current_validation_errors = validate_current_candidate_summary(current_summary) if current_configured else []
    upgrade = previous_candidate_upgrade_summary(
        previous_summary,
        current_summary,
        config,
        previous_validation_errors,
        current_configured,
    )
    if previous_validation_errors or current_validation_errors:
        status = "fail"
        summary = "Configured candidate summary evidence failed validation."
    elif not previous_present and require_previous:
        status = "fail"
        summary = "Previous beta candidate summary is required but was not provided."
    elif not previous_present:
        status = "warn"
        summary = "Previous beta candidate summary was not provided; simulated upgrade evidence was used."
    else:
        status = "pass"
        summary = "Previous beta candidate summary was consumed and current upgrade evidence was represented."
    catalog_transition = upgrade["catalogTransition"]
    support_bundle = upgrade["supportBundleAfterFailedUpgrade"]
    evidence = {
        "evidenceId": "multi-node-beta.upgrade-drill",
        "previousVersion": previous["version"],
        "currentVersion": current["version"],
        "previousReleaseId": upgrade["previousCandidate"]["releaseId"],
        "previousSummaryDrillDigest": upgrade["previousCandidate"]["drillDigest"],
        "previousCatalogChannel": previous["catalogChannel"],
        "currentCatalogChannel": current["catalogChannel"],
        "previousStableCatalogEdition": catalog_transition["previousStableEdition"],
        "previousBetaCatalogEdition": catalog_transition["previousBetaEdition"],
        "currentCatalogEdition": catalog_transition["currentEdition"],
        "previousSummaryConfigured": previous_configured,
        "previousSummaryProvided": previous_present,
        "previousSummaryValid": previous_present and not previous_validation_errors,
        "previousSummaryValidationErrors": previous_validation_errors,
        "previousSummaryStatus": str(previous_summary.get("status", "missing")) if previous_summary else "missing",
        "currentProductionBetaSummaryConfigured": current_configured,
        "currentProductionBetaSummaryProvided": current_present,
        "currentProductionBetaSummaryValid": current_present and not current_validation_errors,
        "currentProductionBetaValidationErrors": current_validation_errors,
        "currentProductionBetaStatus": str(current_summary.get("status", "missing")) if current_summary else "missing",
        "currentUpgradePathRepresented": True,
        "daemonUpgrade": upgrade["daemonUpgrade"],
        "appMigrations": upgrade["appMigrations"],
        "backupRestore": upgrade["backupRestore"],
        "failedMigration": upgrade["failedMigration"],
        "socialInboxMigration": upgrade["socialInboxMigration"],
        "trustGraphMigration": upgrade["trustGraphMigration"],
        "supportBundleAfterFailedUpgrade": support_bundle,
        "firstPartyAppMigrationStatus": upgrade["appMigrationStatus"],
        "backupBeforeUpdateStatus": "pass",
        "restoreIntoCleanNodeStatus": "pass",
        "socialInboxMigrationStatus": upgrade["socialInboxMigration"]["status"],
        "trustGraphMigrationStatus": upgrade["trustGraphMigration"]["status"],
        "supportBundleRedactionStatus": support_bundle["redactionStatus"],
        "rollbackStatus": upgrade["failedMigration"]["rollbackResult"],
        "rawDataIncluded": False,
        "releaseReport": upgrade["releaseReport"],
        "strictPreviousSummaryRequired": require_previous,
    }
    return scenario_result("upgrade-from-previous-candidate", status, summary, evidence)


SCENARIO_BUILDERS = {
    "catalogUpdate": catalog_channel_update,
    "appInstallUpdateRollback": app_install_update_rollback,
    "appDataMigration": app_data_migration,
    "backupRestore": backup_restore,
    "subscriptionPressure": subscription_pressure,
    "trustGraphImport": trust_graph_import,
    "socialInboxMultiSource": social_inbox_multi_source,
    "supportBundleDrill": support_bundle_drill,
}


def collect_live_reachability(config: dict[str, Any], require_live: bool) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    warnings: list[str] = []
    blockers: list[str] = []
    results: list[dict[str, Any]] = []
    for node in config["nodes"]:
        raw_url = str(node.get("baseUrl", "")).strip()
        if not raw_url:
            results.append({"nodeId": node["id"], "configured": False, "reachable": False})
            continue
        safe = is_localhost_url(raw_url)
        reachable = reachable_local_node(raw_url) if safe else False
        if not safe:
            blockers.append(
                f"live node {node['id']} has unsafe baseUrl; live URLs must be localhost-only "
                "without credentials, query, or fragment"
            )
        results.append(
            {
                "nodeId": node["id"],
                "configured": True,
                "baseUrlShape": safe_url_shape(raw_url),
                "localhostOnly": safe,
                "reachable": reachable,
            }
        )
    reachable_count = sum(1 for result in results if result.get("reachable") is True)
    if require_live and reachable_count == 0:
        blockers.append("live mode required at least one reachable localhost node")
    elif reachable_count == 0:
        warnings.append("live mode did not reach a localhost node; deterministic scenario evidence was used")
    return results, warnings, blockers


def safe_json_key_location(key: str) -> str:
    lowered = key.lower()
    sensitive_markers = (
        "authorization",
        "insert",
        "key",
        "password",
        "path",
        "private",
        "raw",
        "secret",
        "token",
        "uri",
    )
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", key) and not any(
        marker in lowered for marker in sensitive_markers
    ):
        return f".{key}"
    return ".<key>"


def add_json_locations(value: Any, path: str = "$", field_names: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}{safe_json_key_location(key_text)}"
            entries.append((f"{child_path}.__key__", key_text))
            entries.extend(add_json_locations(child, child_path, (*field_names, str(key))))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            entries.extend(add_json_locations(child, f"{path}[{index}]", field_names))
    elif isinstance(value, str):
        entries.append((path, value))
        for field_name in reversed(field_names):
            entries.append((path, f"{field_name}={value}"))
    return entries


def redacted_value(raw_value: str) -> bool:
    value = raw_value.strip().strip("'\"").rstrip(",;")
    return value.lower() in REDACTED_SENTINELS


def route_like_path(path: str) -> bool:
    candidate = path.rstrip(".,:;")
    return any(
        candidate == prefix or candidate.startswith(f"{prefix}/") or candidate.startswith(f"{prefix}#")
        for prefix in SAFE_ROUTE_PREFIXES
    )


def contains_local_posix_path(text: str) -> bool:
    for match in POSIX_ABSOLUTE_PATH_RE.finditer(text):
        if not route_like_path(match.group(0)):
            return True
    return False


def add_value_finding(findings: list[dict[str, str]], text: str, location: str, kind: str, regex: re.Pattern[str]) -> None:
    for match in regex.finditer(text):
        group = match.group(1) if match.lastindex else match.group(0)
        if not redacted_value(group):
            findings.append({"location": location, "kind": kind})
            return


def scan_redaction_text(text: str, location: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    direct_checks = (
        ("private-insert-uri", PRIVATE_INSERT_URI_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("bearer-token", BEARER_RE),
        ("file-uri-local-path", FILE_URI_RE),
        ("windows-local-path", WINDOWS_PATH_RE),
    )
    for kind, regex in direct_checks:
        if regex.search(text):
            findings.append({"location": location, "kind": kind})
    if contains_local_posix_path(text):
        findings.append({"location": location, "kind": "host-local-path"})
    add_value_finding(findings, text, location, "authorization-header", AUTH_HEADER_RE)
    add_value_finding(findings, text, location, "app-or-session-token", TOKEN_VALUE_RE)
    add_value_finding(findings, text, location, "form-password", FORM_PASSWORD_VALUE_RE)
    add_value_finding(findings, text, location, "ci-secret-value", CI_SECRET_VALUE_RE)
    add_value_finding(findings, text, location, "raw-fetched-content", RAW_FETCHED_CONTENT_RE)
    add_value_finding(findings, text, location, "raw-app-data", RAW_APP_DATA_RE)
    add_value_finding(findings, text, location, "raw-social-message", RAW_SOCIAL_MESSAGE_RE)
    add_value_finding(findings, text, location, "raw-trust-statement", RAW_TRUST_STATEMENT_RE)
    add_value_finding(findings, text, location, "raw-backup-payload", RAW_BACKUP_PAYLOAD_RE)
    add_value_finding(findings, text, location, "raw-signature", RAW_SIGNATURE_RE)
    if "._" in text:
        findings.append({"location": location, "kind": "appledouble-artifact"})
    if "__MACOSX" in text:
        findings.append({"location": location, "kind": "macosx-artifact-directory"})
    return findings


def scan_redaction_payload(summary: dict[str, Any], report: str = "") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for location, text in add_json_locations(summary):
        findings.extend(scan_redaction_text(text, location))
    if report:
        findings.extend(scan_redaction_text(report, "markdown-report"))
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding["location"], finding["kind"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def normalized_field_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def sensitive_safety_flag_mode(name: str) -> str:
    normalized = normalized_field_name(name)
    if not any(marker in normalized for marker in SENSITIVE_SAFETY_FLAG_MARKERS):
        return ""
    if normalized.endswith("included"):
        return "must-be-false"
    if (
        normalized.endswith("redacted")
        or normalized.endswith("excluded")
        or normalized.endswith("excludedfromevidence")
    ):
        return "must-be-true"
    return ""


def validate_evidence_safety_flags(value: Any, location: str) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            field = str(key)
            child_location = f"{location}.{field}"
            normalized = normalized_field_name(field)
            if normalized == "redactionscanstatus":
                if str(child).strip().lower() != "pass":
                    errors.append(f"redaction safety violation: redaction-scan-status at {child_location}")
            mode = sensitive_safety_flag_mode(field)
            if mode:
                if not isinstance(child, bool):
                    errors.append(f"redaction safety violation: malformed-safety-flag at {child_location}")
                elif mode == "must-be-false" and child is True:
                    errors.append(f"redaction safety violation: forbidden-included-flag at {child_location}")
                elif mode == "must-be-true" and child is False:
                    errors.append(f"redaction safety violation: missing-redaction-flag at {child_location}")
            errors.extend(validate_evidence_safety_flags(child, child_location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(validate_evidence_safety_flags(child, f"{location}[{index}]"))
    return errors


def validate_redaction_checks(redaction: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    checks = redaction.get("checks")
    if not isinstance(checks, dict):
        return ["redaction safety violation: missing-redaction-checks at redaction.checks"]
    for key in sorted(set(checks) - set(REDACTION_KEYS)):
        errors.append(f"redaction safety violation: unsupported-redaction-check at redaction.checks.{key}")
    for key in REDACTION_KEYS:
        value = checks.get(key)
        if value is True:
            continue
        if key not in checks:
            errors.append(f"redaction safety violation: missing-redaction-check at redaction.checks.{key}")
        elif not isinstance(value, bool):
            errors.append(f"redaction safety violation: malformed-redaction-check at redaction.checks.{key}")
        else:
            errors.append(f"redaction safety violation: disabled-redaction-check at redaction.checks.{key}")
    return errors


def summarize_status(scenarios: list[dict[str, Any]], redaction_status: str, blockers: list[str], warnings: list[str]) -> str:
    if blockers or redaction_status == "fail" or any(scenario["status"] == "fail" for scenario in scenarios):
        return "fail"
    if warnings or redaction_status == "warn" or any(scenario["status"] == "warn" for scenario in scenarios):
        return "warn"
    return "pass"


def build_summary(
    config: dict[str, Any],
    *,
    out_dir: Path | None = None,
    require_live: bool = False,
    require_all_scenarios: bool = False,
    strict: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    base = base_dir or Path.cwd()
    scenario_strict = strict or require_all_scenarios or bool(config["strict"].get("requireAllScenarios"))
    scenarios: list[dict[str, Any]] = []
    warnings: list[str] = []
    blockers: list[str] = []

    for config_key, builder in SCENARIO_BUILDERS.items():
        if config["scenarios"].get(config_key) is not True:
            scenarios.append(disabled_scenario(config_key, scenario_strict))
        else:
            scenarios.append(builder(config))
    if config["scenarios"].get("upgradeFromPreviousCandidate") is not True:
        scenarios.append(disabled_scenario("upgradeFromPreviousCandidate", scenario_strict))
    else:
        scenarios.append(upgrade_from_previous_candidate(config, base, strict))

    for scenario in scenarios:
        if scenario["status"] == "fail":
            blockers.append(f"{scenario['id']} failed")
        elif scenario["status"] == "warn":
            warnings.append(f"{scenario['id']} has warnings")

    live_reachability: list[dict[str, Any]] = []
    if config["mode"] == "live":
        live_reachability, live_warnings, live_blockers = collect_live_reachability(config, require_live)
        warnings.extend(live_warnings)
        blockers.extend(live_blockers)
    elif require_live:
        blockers.append("--require-live can only be satisfied in live mode")

    summary: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUMMARY_KIND,
        "generatedAt": DETERMINISTIC_GENERATED_AT,
        "status": "pass",
        "promotionReady": False,
        "mode": config["mode"],
        "durationProfile": config["durationProfile"],
        "previousCandidate": {
            "version": config["previousCandidate"]["version"],
            "catalogChannel": config["previousCandidate"]["catalogChannel"],
            "summaryProvided": bool(config["previousCandidate"].get("summaryPath")),
        },
        "currentCandidate": {
            "version": config["currentCandidate"]["version"],
            "catalogChannel": config["currentCandidate"]["catalogChannel"],
            "productionBetaSummaryProvided": bool(config["currentCandidate"].get("productionBetaSummaryPath")),
        },
        "nodes": [safe_node_summary(node) for node in config["nodes"]],
        "topology": {
            "nodeCount": len(config["nodes"]),
            "roles": sorted({node["role"] for node in config["nodes"]}),
            "catalogChannels": sorted({channel for node in config["nodes"] for channel in node["catalogChannels"]}),
            "firstPartyAppsCovered": sorted(node_app_ids(config["nodes"]).intersection(FIRST_PARTY_APPS)),
            "liveReachability": live_reachability,
        },
        "scenarios": scenarios,
        "scenarioStatuses": {scenario["id"]: scenario["status"] for scenario in scenarios},
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "redaction": {
            "status": "pass",
            "findings": [],
            "checks": config["redaction"],
        },
        "artifacts": {
            "markdownReport": REPORT_FILE_NAME,
            "rawSummary": SUMMARY_FILE_NAME,
        },
    }
    report = render_report(summary)
    findings = scan_redaction_payload(summary, report)
    if findings:
        summary["redaction"] = {
            "status": "fail",
            "findings": findings,
            "checks": config["redaction"],
        }
        summary["blockers"] = sorted(set([*summary["blockers"], "redaction scan failed"]))
    summary["status"] = summarize_status(
        scenarios,
        str(summary["redaction"]["status"]),
        [str(value) for value in summary["blockers"]],
        [str(value) for value in summary["warnings"]],
    )
    acceptable_statuses = {"pass"} if strict else {"pass", "warn"}
    summary["promotionReady"] = summary["status"] in acceptable_statuses and summary["redaction"]["status"] == "pass"
    return summary


def plan_candidate(candidate: dict[str, Any], summary_key: str, configured_key: str) -> dict[str, Any]:
    return {
        "version": candidate["version"],
        "catalogChannel": candidate["catalogChannel"],
        configured_key: bool(candidate.get(summary_key)),
    }


def render_plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "mode": config["mode"],
        "durationProfile": config["durationProfile"],
        "previousCandidate": plan_candidate(
            config["previousCandidate"],
            "summaryPath",
            "summaryConfigured",
        ),
        "currentCandidate": plan_candidate(
            config["currentCandidate"],
            "productionBetaSummaryPath",
            "productionBetaSummaryConfigured",
        ),
        "nodeCount": len(config["nodes"]),
        "nodes": [safe_node_summary(node) for node in config["nodes"]],
        "scenarioIds": [SCENARIO_IDS[key] for key in REQUIRED_SCENARIOS if config["scenarios"].get(key) is True],
        "disabledScenarioIds": [
            SCENARIO_IDS[key] for key in REQUIRED_SCENARIOS if config["scenarios"].get(key) is not True
        ],
        "redactionChecks": config["redaction"],
    }


def render_report(summary: dict[str, Any]) -> str:
    redaction = summary.get("redaction")
    redaction_status = redaction.get("status", "missing") if isinstance(redaction, dict) else "missing"
    nodes = summary.get("nodes")
    node_count = len(nodes) if isinstance(nodes, list) else 0
    scenarios = summary.get("scenarios")
    scenario_entries = scenarios if isinstance(scenarios, list) else []
    blockers = summary.get("blockers")
    blocker_entries = blockers if isinstance(blockers, list) else []
    warnings = summary.get("warnings")
    warning_entries = warnings if isinstance(warnings, list) else []
    lines = [
        "# Multi-node Beta Soak Summary",
        "",
        f"- Mode: `{summary.get('mode', 'missing')}`",
        f"- Duration profile: `{summary.get('durationProfile', 'missing')}`",
        f"- Status: `{summary.get('status', 'missing')}`",
        f"- Promotion ready: `{str(summary.get('promotionReady', False)).lower()}`",
        f"- Redaction: `{redaction_status}`",
        f"- Nodes: `{node_count}`",
        "",
        "## Scenarios",
        "",
        "| Scenario | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for scenario in scenario_entries:
        if not isinstance(scenario, dict):
            continue
        lines.append(
            "| `{id}` | `{status}` | {summary_text} |".format(
                id=scenario.get("id", "missing"),
                status=scenario.get("status", "missing"),
                summary_text=str(scenario.get("summary", "")).replace("|", "\\|"),
            )
        )
    if blocker_entries:
        lines.extend(["", "## Blockers", ""])
        for blocker in blocker_entries:
            lines.append(f"- {blocker}")
    if warning_entries:
        lines.extend(["", "## Warnings", ""])
        for warning in warning_entries:
            lines.append(f"- {warning}")
    findings = redaction.get("findings", []) if isinstance(redaction, dict) else []
    finding_entries = findings if isinstance(findings, list) else []
    if finding_entries:
        lines.extend(["", "## Redaction Findings", ""])
        for finding in finding_entries:
            if isinstance(finding, dict):
                lines.append(f"- `{finding.get('kind', 'unknown')}` at `{finding.get('location', 'unknown')}`")
    lines.append("")
    return "\n".join(lines)


def scenario_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    scenarios = summary.get("scenarios", [])
    if not isinstance(scenarios, list):
        return {}
    return {str(item.get("id")): item for item in scenarios if isinstance(item, dict)}


def is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def validate_candidate_metadata(value: Any, name: str, provided_key: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{name} must be an object"]
    if not isinstance(value.get("version"), str) or not value.get("version", "").strip():
        errors.append(f"{name}.version must be a non-empty string")
    if value.get("catalogChannel") not in CATALOG_CHANNELS:
        errors.append(f"{name}.catalogChannel is invalid")
    if not isinstance(value.get(provided_key), bool):
        errors.append(f"{name}.{provided_key} must be boolean")
    return errors


def validate_summary_nodes(nodes: Any) -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    valid_nodes: list[dict[str, Any]] = []
    if not isinstance(nodes, list) or len(nodes) < 2:
        return ["nodes must include at least two entries"], valid_nodes
    seen_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] must be an object")
            continue
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id.strip():
            errors.append(f"nodes[{index}].id must be a non-empty string")
        elif node_id in seen_ids:
            errors.append(f"nodes[{index}].id must be unique")
        else:
            seen_ids.add(node_id)
        if node.get("role") not in NODE_ROLES:
            errors.append(f"nodes[{index}].role is invalid")
        if not is_string_list(node.get("catalogChannels")) or not node.get("catalogChannels"):
            errors.append(f"nodes[{index}].catalogChannels must be a non-empty string list")
        else:
            invalid_channels = sorted(set(node["catalogChannels"]) - set(CATALOG_CHANNELS))
            if invalid_channels:
                errors.append(f"nodes[{index}].catalogChannels contains invalid channels")
        if not is_string_list(node.get("apps")) or not node.get("apps"):
            errors.append(f"nodes[{index}].apps must be a non-empty string list")
        if isinstance(node_id, str) and node.get("role") in NODE_ROLES and is_string_list(
            node.get("catalogChannels")
        ) and is_string_list(node.get("apps")):
            valid_nodes.append(node)
    return errors, valid_nodes


def validate_topology(topology: Any, nodes: Any, valid_nodes: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if not isinstance(topology, dict):
        return ["topology must be an object"]
    if not isinstance(topology.get("nodeCount"), int):
        errors.append("topology.nodeCount must be an integer")
    elif isinstance(nodes, list) and topology["nodeCount"] != len(nodes):
        errors.append("topology.nodeCount must match nodes length")
    expected_roles = sorted({str(node["role"]) for node in valid_nodes})
    if not is_string_list(topology.get("roles")):
        errors.append("topology.roles must be a string list")
    elif topology["roles"] != expected_roles:
        errors.append("topology.roles must match node roles")
    expected_channels = sorted({str(channel) for node in valid_nodes for channel in node["catalogChannels"]})
    if not is_string_list(topology.get("catalogChannels")):
        errors.append("topology.catalogChannels must be a string list")
    elif topology["catalogChannels"] != expected_channels:
        errors.append("topology.catalogChannels must match node catalog channels")
    expected_apps = sorted(node_app_ids(valid_nodes).intersection(FIRST_PARTY_APPS))
    covered_apps = topology.get("firstPartyAppsCovered")
    if not is_string_list(covered_apps):
        errors.append("topology.firstPartyAppsCovered must be a string list")
    else:
        if covered_apps != expected_apps:
            errors.append("topology.firstPartyAppsCovered must match node app coverage")
        missing_required_apps = sorted(set(REQUIRED_LIFECYCLE_APPS) - set(covered_apps))
        if missing_required_apps:
            errors.append("topology.firstPartyAppsCovered must include required lifecycle apps")
    if not isinstance(topology.get("liveReachability"), list):
        errors.append("topology.liveReachability must be a list")
    return errors


def validate_scenario_statuses(summary: dict[str, Any], scenario_entries: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    statuses = summary.get("scenarioStatuses")
    if not isinstance(statuses, dict):
        return ["scenarioStatuses must be an object"]
    for scenario_id in SCENARIO_EVIDENCE_IDS:
        entry = scenario_entries.get(scenario_id)
        if entry is None:
            continue
        if statuses.get(scenario_id) != entry.get("status"):
            errors.append(f"scenarioStatuses.{scenario_id} must match scenario status")
    return errors


def validate_catalog_channel_update_evidence(entry: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    signature = evidence.get("catalogSignatureEvidence")
    if not isinstance(signature, dict):
        errors.append("scenario catalog-channel-update catalogSignatureEvidence must be an object")
    else:
        for field in ("catalogDigest", "signatureKeyId", "reviewChainDigest"):
            if not isinstance(signature.get(field), str) or not signature.get(field, "").strip():
                errors.append(f"scenario catalog-channel-update catalogSignatureEvidence missing {field}")

    blocked_nodes = evidence.get("nodesWithBlockedCatalogChannels")
    if "nodesWithBlockedCatalogChannels" in evidence and not isinstance(blocked_nodes, list):
        errors.append("scenario catalog-channel-update nodesWithBlockedCatalogChannels must be a list")

    if entry.get("status") != "pass":
        return errors

    for field in (
        "stableNodesBlockBetaAndNightly",
        "betaNodesOptInExplicitly",
        "nightlyCandidatesBlocked",
        "deprecatedCandidatesBlocked",
        "denylistedCandidatesBlocked",
    ):
        if evidence.get(field) is not True:
            errors.append(f"scenario catalog-channel-update pass requires {field}")
    for field in ("stableOnlyNodeCount", "betaOptInNodeCount"):
        value = evidence.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(f"scenario catalog-channel-update pass requires {field}")
    if blocked_nodes:
        errors.append("scenario catalog-channel-update pass requires empty nodesWithBlockedCatalogChannels")
    return errors


def validate_required_evidence_fields(
    scenario_id: str,
    entry: dict[str, Any],
    evidence: dict[str, Any],
    summary: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if evidence.get("configured") is False:
        if entry.get("status") == "pass":
            errors.append(f"scenario {scenario_id} cannot pass when configured is false")
        if not isinstance(evidence.get("strict"), bool):
            errors.append(f"scenario {scenario_id} disabled evidence must include strict")
        return errors
    for field in REQUIRED_SCENARIO_EVIDENCE_FIELDS.get(scenario_id, ()):
        if field not in evidence:
            errors.append(f"scenario {scenario_id} evidence missing {field}")
    if scenario_id == "catalog-channel-update":
        errors.extend(validate_catalog_channel_update_evidence(entry, evidence))
    if scenario_id == "app-install-update-rollback":
        installed_apps = evidence.get("installedFirstPartyApps")
        if not is_string_list(installed_apps) or not set(REQUIRED_LIFECYCLE_APPS).issubset(set(installed_apps)):
            errors.append("scenario app-install-update-rollback installedFirstPartyApps must include required apps")
        updated_apps = evidence.get("updatedApps")
        if not is_string_list(updated_apps) or not set(REQUIRED_LIFECYCLE_APPS).issubset(set(updated_apps)):
            errors.append("scenario app-install-update-rollback updatedApps must include required apps")
    if scenario_id == "app-data-migration":
        apps = evidence.get("apps")
        if not isinstance(apps, dict):
            errors.append("scenario app-data-migration apps must be an object")
        else:
            for app in REQUIRED_LIFECYCLE_APPS:
                app_evidence = apps.get(app)
                if not isinstance(app_evidence, dict):
                    errors.append(f"scenario app-data-migration apps.{app} must be an object")
                    continue
                for field in (
                    "fromSchema",
                    "toSchema",
                    "dryRunDigest",
                    "backupBeforeUpdateRequired",
                    "rawAppDataIncluded",
                ):
                    if field not in app_evidence:
                        errors.append(f"scenario app-data-migration apps.{app} missing {field}")
    if scenario_id == "backup-restore":
        exported_apps = evidence.get("exportedApps")
        if not is_string_list(exported_apps) or not set(REQUIRED_LIFECYCLE_APPS).issubset(set(exported_apps)):
            errors.append("scenario backup-restore exportedApps must include required apps")
    if scenario_id == "upgrade-from-previous-candidate":
        previous = summary.get("previousCandidate")
        current = summary.get("currentCandidate")
        previous_errors = evidence.get("previousSummaryValidationErrors")
        previous_error_entries = previous_errors if isinstance(previous_errors, list) else []
        current_errors = evidence.get("currentProductionBetaValidationErrors")
        current_error_entries = current_errors if isinstance(current_errors, list) else []
        for field in (
            "previousSummaryConfigured",
            "previousSummaryProvided",
            "previousSummaryValid",
            "currentProductionBetaSummaryConfigured",
            "currentProductionBetaSummaryProvided",
            "currentProductionBetaSummaryValid",
            "currentUpgradePathRepresented",
            "strictPreviousSummaryRequired",
        ):
            if not isinstance(evidence.get(field), bool):
                errors.append(f"scenario upgrade-from-previous-candidate {field} must be boolean")
        if not isinstance(previous_errors, list):
            errors.append(
                "scenario upgrade-from-previous-candidate previousSummaryValidationErrors must be a list"
            )
        if not isinstance(current_errors, list):
            errors.append(
                "scenario upgrade-from-previous-candidate currentProductionBetaValidationErrors must be a list"
            )
        drill_digest = evidence.get("previousSummaryDrillDigest")
        if not isinstance(drill_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", drill_digest):
            errors.append("scenario upgrade-from-previous-candidate previousSummaryDrillDigest must be a sha256 digest")
        if isinstance(previous, dict):
            if evidence.get("previousVersion") != previous.get("version"):
                errors.append("scenario upgrade-from-previous-candidate previousVersion must match previousCandidate")
            if evidence.get("previousSummaryConfigured") != previous.get("summaryProvided"):
                errors.append(
                    "scenario upgrade-from-previous-candidate previousSummaryConfigured must match previousCandidate"
                )
        if isinstance(current, dict):
            if evidence.get("currentVersion") != current.get("version"):
                errors.append("scenario upgrade-from-previous-candidate currentVersion must match currentCandidate")
            if evidence.get("currentProductionBetaSummaryConfigured") != current.get(
                "productionBetaSummaryProvided"
            ):
                errors.append(
                    "scenario upgrade-from-previous-candidate currentProductionBetaSummaryConfigured must match "
                    "currentCandidate"
                )
        if evidence.get("previousSummaryProvided") is True and evidence.get("previousSummaryConfigured") is not True:
            errors.append(
                "scenario upgrade-from-previous-candidate previousSummaryProvided requires previousSummaryConfigured"
            )
        if evidence.get("previousSummaryValid") is True:
            if evidence.get("previousSummaryProvided") is not True:
                errors.append(
                    "scenario upgrade-from-previous-candidate previousSummaryValid requires previousSummaryProvided"
                )
            if previous_error_entries:
                errors.append(
                    "scenario upgrade-from-previous-candidate previousSummaryValid requires empty "
                    "previousSummaryValidationErrors"
                )
        if evidence.get("currentProductionBetaSummaryProvided") is True and evidence.get(
            "currentProductionBetaSummaryConfigured"
        ) is not True:
            errors.append(
                "scenario upgrade-from-previous-candidate currentProductionBetaSummaryProvided requires "
                "currentProductionBetaSummaryConfigured"
            )
        if evidence.get("currentProductionBetaSummaryValid") is True:
            if evidence.get("currentProductionBetaSummaryProvided") is not True:
                errors.append(
                    "scenario upgrade-from-previous-candidate currentProductionBetaSummaryValid requires "
                    "currentProductionBetaSummaryProvided"
                )
            if current_error_entries:
                errors.append(
                    "scenario upgrade-from-previous-candidate currentProductionBetaSummaryValid requires empty "
                    "currentProductionBetaValidationErrors"
                )
        daemon_upgrade = evidence.get("daemonUpgrade")
        if not isinstance(daemon_upgrade, dict):
            errors.append("scenario upgrade-from-previous-candidate daemonUpgrade must be an object")
        else:
            if daemon_upgrade.get("represented") is not True:
                errors.append("scenario upgrade-from-previous-candidate daemonUpgrade.represented must be true")
            if daemon_upgrade.get("status") != "pass":
                errors.append("scenario upgrade-from-previous-candidate daemonUpgrade.status must be pass")
        app_migrations = evidence.get("appMigrations")
        if not isinstance(app_migrations, list):
            errors.append("scenario upgrade-from-previous-candidate appMigrations must be a list")
            app_migration_apps: set[str] = set()
        else:
            app_migration_apps = {
                str(entry.get("appId"))
                for entry in app_migrations
                if isinstance(entry, dict) and isinstance(entry.get("appId"), str)
            }
            missing_migration_apps = sorted(set(PREVIOUS_CANDIDATE_MIGRATION_APPS) - app_migration_apps)
            if missing_migration_apps:
                errors.append(
                    "scenario upgrade-from-previous-candidate appMigrations missing required apps: "
                    + ", ".join(missing_migration_apps)
                )
            for index, migration in enumerate(app_migrations):
                if not isinstance(migration, dict):
                    errors.append(f"scenario upgrade-from-previous-candidate appMigrations[{index}] must be an object")
                    continue
                if migration.get("status") != "pass":
                    errors.append(
                        f"scenario upgrade-from-previous-candidate appMigrations[{index}].status must be pass"
                    )
                if migration.get("backupBeforeUpdateRequired") is not True:
                    errors.append(
                        "scenario upgrade-from-previous-candidate "
                        f"appMigrations[{index}].backupBeforeUpdateRequired must be true"
                    )
                if migration.get("rawAppDataIncluded") is not False:
                    errors.append(
                        "scenario upgrade-from-previous-candidate "
                        f"appMigrations[{index}].rawAppDataIncluded must be false"
                    )
        backup_restore_evidence = evidence.get("backupRestore")
        if not isinstance(backup_restore_evidence, dict):
            errors.append("scenario upgrade-from-previous-candidate backupRestore must be an object")
        else:
            for field, expected in (
                ("status", "pass"),
                ("backupBeforeUpdate", True),
                ("restoredIntoCleanNode", True),
                ("rawBackupPayloadIncluded", False),
                ("rawAppDataIncluded", False),
            ):
                if backup_restore_evidence.get(field) != expected:
                    errors.append(f"scenario upgrade-from-previous-candidate backupRestore.{field} must be {expected}")
        failed_migration = evidence.get("failedMigration")
        if not isinstance(failed_migration, dict):
            errors.append("scenario upgrade-from-previous-candidate failedMigration must be an object")
        else:
            for field, expected in (
                ("status", "pass"),
                ("blocksUpdate", True),
                ("triggersRollback", True),
                ("rollbackResult", "pass"),
            ):
                if failed_migration.get(field) != expected:
                    errors.append(f"scenario upgrade-from-previous-candidate failedMigration.{field} must be {expected}")
        social_migration = evidence.get("socialInboxMigration")
        if not isinstance(social_migration, dict):
            errors.append("scenario upgrade-from-previous-candidate socialInboxMigration must be an object")
        elif social_migration.get("status") != "pass" or social_migration.get("rawMessageBodiesIncluded") is not False:
            errors.append(
                "scenario upgrade-from-previous-candidate socialInboxMigration must pass without raw message bodies"
            )
        trust_migration = evidence.get("trustGraphMigration")
        if not isinstance(trust_migration, dict):
            errors.append("scenario upgrade-from-previous-candidate trustGraphMigration must be an object")
        elif trust_migration.get("status") != "pass" or trust_migration.get("rawStatementsIncluded") is not False:
            errors.append(
                "scenario upgrade-from-previous-candidate trustGraphMigration must pass without raw statements"
            )
        failed_support = evidence.get("supportBundleAfterFailedUpgrade")
        if not isinstance(failed_support, dict):
            errors.append("scenario upgrade-from-previous-candidate supportBundleAfterFailedUpgrade must be an object")
        else:
            for field, expected in (
                ("status", "pass"),
                ("redactionStatus", "pass"),
                ("rawContentIncluded", False),
                ("rawAppDataIncluded", False),
                ("tokensIncluded", False),
                ("privateInsertUrisIncluded", False),
                ("absolutePathsIncluded", False),
            ):
                if failed_support.get(field) != expected:
                    errors.append(
                        "scenario upgrade-from-previous-candidate "
                        f"supportBundleAfterFailedUpgrade.{field} must be {expected}"
                    )
        release_report = evidence.get("releaseReport")
        if not isinstance(release_report, dict):
            errors.append("scenario upgrade-from-previous-candidate releaseReport must be an object")
        else:
            for field, expected in (
                ("status", "pass"),
                ("digestsOnly", True),
                ("countsOnly", True),
                ("rawDataIncluded", False),
            ):
                if release_report.get(field) != expected:
                    errors.append(f"scenario upgrade-from-previous-candidate releaseReport.{field} must be {expected}")
        if evidence.get("rawDataIncluded") is not False:
            errors.append("scenario upgrade-from-previous-candidate rawDataIncluded must be false")
        if entry.get("status") == "pass":
            if evidence.get("previousSummaryConfigured") is not True:
                errors.append(
                    "scenario upgrade-from-previous-candidate pass requires previousSummaryConfigured"
                )
            if evidence.get("previousSummaryProvided") is not True:
                errors.append("scenario upgrade-from-previous-candidate pass requires previousSummaryProvided")
            if evidence.get("previousSummaryValid") is not True:
                errors.append("scenario upgrade-from-previous-candidate pass requires previousSummaryValid")
            if previous_error_entries:
                errors.append(
                    "scenario upgrade-from-previous-candidate pass requires empty previousSummaryValidationErrors"
                )
            if evidence.get("currentProductionBetaSummaryConfigured") is True:
                if evidence.get("currentProductionBetaSummaryProvided") is not True:
                    errors.append(
                        "scenario upgrade-from-previous-candidate pass requires "
                        "currentProductionBetaSummaryProvided when configured"
                    )
                if evidence.get("currentProductionBetaSummaryValid") is not True:
                    errors.append(
                        "scenario upgrade-from-previous-candidate pass requires "
                        "currentProductionBetaSummaryValid when configured"
                    )
                if current_error_entries:
                    errors.append(
                        "scenario upgrade-from-previous-candidate pass requires empty "
                        "currentProductionBetaValidationErrors when configured"
                    )
            for field in (
                "currentUpgradePathRepresented",
                "firstPartyAppMigrationStatus",
                "backupBeforeUpdateStatus",
                "restoreIntoCleanNodeStatus",
                "socialInboxMigrationStatus",
                "trustGraphMigrationStatus",
                "supportBundleRedactionStatus",
                "rollbackStatus",
            ):
                expected = True if field == "currentUpgradePathRepresented" else "pass"
                if evidence.get(field) != expected:
                    errors.append(f"scenario upgrade-from-previous-candidate pass requires {field}")
    return errors


def validate_summary(summary: dict[str, Any] | None, *, strict: bool = False) -> list[str]:
    errors: list[str] = []
    if summary is None:
        return ["summary is missing or malformed"]
    if summary.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("schemaVersion must be 1")
    if summary.get("kind") != SUMMARY_KIND:
        errors.append(f"kind must be {SUMMARY_KIND}")
    if summary.get("mode") not in MODES:
        errors.append("mode must be simulated, hybrid, or live")
    if summary.get("durationProfile") not in DURATION_PROFILES:
        errors.append("durationProfile is invalid")
    if not isinstance(summary.get("generatedAt"), str) or not summary.get("generatedAt", "").strip():
        errors.append("generatedAt must be a non-empty string")
    if summary.get("status") not in {"pass", "warn", "fail"}:
        errors.append("status must be pass, warn, or fail")
    if not isinstance(summary.get("promotionReady"), bool):
        errors.append("promotionReady must be boolean")
    errors.extend(validate_candidate_metadata(summary.get("previousCandidate"), "previousCandidate", "summaryProvided"))
    errors.extend(
        validate_candidate_metadata(
            summary.get("currentCandidate"),
            "currentCandidate",
            "productionBetaSummaryProvided",
        )
    )
    blockers = summary.get("blockers", [])
    blocker_entries: list[Any] = []
    if not isinstance(blockers, list):
        errors.append("blockers must be a list")
    else:
        blocker_entries = blockers
    warnings = summary.get("warnings", [])
    warning_entries: list[Any] = []
    if not isinstance(warnings, list):
        errors.append("warnings must be a list")
    else:
        warning_entries = warnings
    nodes = summary.get("nodes")
    node_errors, valid_nodes = validate_summary_nodes(nodes)
    errors.extend(node_errors)
    errors.extend(validate_topology(summary.get("topology"), nodes, valid_nodes))
    scenario_entries = scenario_map(summary)
    errors.extend(validate_scenario_statuses(summary, scenario_entries))
    for scenario_id in SCENARIO_EVIDENCE_IDS:
        entry = scenario_entries.get(scenario_id)
        if entry is None:
            errors.append(f"missing scenario {scenario_id}")
            continue
        if entry.get("status") not in {"pass", "warn", "fail", "skip"}:
            errors.append(f"scenario {scenario_id} has invalid status")
        evidence = entry.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"scenario {scenario_id} evidence must be an object")
        else:
            if evidence.get("evidenceId") != SCENARIO_EVIDENCE_IDS[scenario_id]:
                errors.append(f"scenario {scenario_id} has wrong evidenceId")
            errors.extend(validate_evidence_safety_flags(evidence, f"scenarios.{scenario_id}.evidence"))
            errors.extend(validate_required_evidence_fields(scenario_id, entry, evidence, summary))
    redaction = summary.get("redaction")
    redaction_status = "missing"
    if not isinstance(redaction, dict):
        errors.append("redaction must be an object")
    else:
        redaction_status = str(redaction.get("status", "missing"))
        if redaction_status not in {"pass", "warn", "fail"}:
            errors.append("redaction.status is invalid")
        findings = redaction.get("findings", [])
        if not isinstance(findings, list):
            errors.append("redaction.findings must be a list")
        elif findings:
            errors.append("redaction findings must be empty")
        errors.extend(validate_redaction_checks(redaction))
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
    elif any(key not in SAFE_SUMMARY_ARTIFACT_KEYS for key in artifacts):
        errors.append("artifacts contains unsupported fields")

    report_text = render_report(summary)
    for finding in scan_redaction_payload(summary, report_text):
        errors.append(f"redaction leak detected: {finding['kind']} at {finding['location']}")

    summary_status = summary.get("status")
    scenario_status_values = {
        scenario_id: (
            str(entry.get("status", "missing"))
            if isinstance(entry := scenario_entries.get(scenario_id), dict)
            else "missing"
        )
        for scenario_id in SCENARIO_EVIDENCE_IDS
    }
    nonpassing_scenarios = [
        scenario_id for scenario_id, status in scenario_status_values.items() if status != "pass"
    ]
    failing_scenarios = [
        scenario_id for scenario_id, status in scenario_status_values.items() if status == "fail"
    ]
    if summary_status == "fail":
        errors.append("summary status is fail")
    if summary_status == "pass" and summary.get("promotionReady") is not True:
        errors.append("promotionReady must be true when summary status is pass")
    if summary_status == "pass" and nonpassing_scenarios:
        errors.append("summary status must not be pass when scenarios are not pass")
    if summary_status == "pass" and redaction_status != "pass":
        errors.append("summary status must not be pass when redaction is not pass")
    if failing_scenarios and summary_status != "fail":
        errors.append("summary status must be fail when scenarios fail")
    if redaction_status == "fail" and summary_status != "fail":
        errors.append("summary status must be fail when redaction fails")
    if blocker_entries and summary_status != "fail":
        errors.append("summary status must be fail when blockers are present")
    if blocker_entries and summary.get("promotionReady") is not False:
        errors.append("promotionReady must be false when blockers are present")
    if warning_entries and not blocker_entries and summary_status == "pass":
        errors.append("summary status must not be pass when warnings are present")
    if strict:
        if summary_status != "pass":
            errors.append("strict summary status must be pass")
        for scenario_id, entry in scenario_entries.items():
            if scenario_id in SCENARIO_EVIDENCE_IDS and entry.get("status") != "pass":
                errors.append(f"strict scenario {scenario_id} must pass")
        if redaction_status != "pass":
            errors.append("strict redaction status must pass")
        if summary.get("promotionReady") is not True:
            errors.append("strict summary must be promotionReady")
    return sorted(set(errors))


def scenario_statuses(summary: dict[str, Any]) -> dict[str, str]:
    return {
        scenario_id: compact_status(entry.get("status", "missing"))
        for scenario_id, entry in scenario_map(summary).items()
        if scenario_id in SCENARIO_EVIDENCE_IDS
    }


def compact_status(value: Any, *, default: str = "missing") -> str:
    text = str(value).strip().lower()
    return text if text in {"pass", "warn", "fail", "missing"} else default


def compact_mode(value: Any) -> str:
    text = str(value).strip()
    return text if text in MODES else "missing"


def compact_duration_profile(value: Any) -> str:
    text = str(value).strip()
    return text if text in DURATION_PROFILES else "missing"


def compact_public_text(value: Any, location: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)) or value is None:
        text = str(value)
    else:
        return "<redacted>"
    return "<redacted>" if scan_redaction_text(text, location) else text


def compact_public_text_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list):
        return []
    return [compact_public_text(item, f"{location}[{index}]") for index, item in enumerate(value)]


def compact_redaction_finding(value: Any, index: int) -> dict[str, str]:
    if not isinstance(value, dict):
        return {
            "kind": "malformed-redaction-finding",
            "location": f"redaction.findings[{index}]",
            "source": "summary",
        }
    return {
        "kind": compact_public_text(value.get("kind", "redaction-finding"), f"redaction.findings[{index}].kind"),
        "location": compact_public_text(
            value.get("location", value.get("path", "redaction.findings")),
            f"redaction.findings[{index}].location",
        ),
        "source": compact_public_text(value.get("source", "summary"), f"redaction.findings[{index}].source"),
    }


def compact_redaction(redaction: Any) -> dict[str, Any]:
    if not isinstance(redaction, dict):
        return {"status": "missing", "findings": [], "checks": {}}
    findings = redaction.get("findings", [])
    return {
        "status": compact_status(redaction.get("status", "missing")),
        "findings": [
            compact_redaction_finding(finding, index)
            for index, finding in enumerate(findings if isinstance(findings, list) else [])
        ],
        "checks": {
            key: redaction.get("checks", {}).get(key)
            for key in REDACTION_KEYS
            if isinstance(redaction.get("checks"), dict) and isinstance(redaction["checks"].get(key), bool)
        },
    }


def compact_previous_candidate_upgrade(summary: dict[str, Any]) -> dict[str, Any]:
    scenario = scenario_map(summary).get("upgrade-from-previous-candidate", {})
    evidence = scenario.get("evidence") if isinstance(scenario, dict) else {}
    if not isinstance(evidence, dict):
        return {"status": "missing"}
    fields = (
        "previousReleaseId",
        "previousSummaryDrillDigest",
        "previousVersion",
        "currentVersion",
        "previousCatalogChannel",
        "currentCatalogChannel",
        "previousStableCatalogEdition",
        "previousBetaCatalogEdition",
        "currentCatalogEdition",
        "previousSummaryConfigured",
        "previousSummaryProvided",
        "previousSummaryValid",
        "previousSummaryStatus",
        "currentProductionBetaSummaryConfigured",
        "currentProductionBetaSummaryProvided",
        "currentProductionBetaSummaryValid",
        "currentProductionBetaStatus",
        "currentUpgradePathRepresented",
        "firstPartyAppMigrationStatus",
        "backupBeforeUpdateStatus",
        "restoreIntoCleanNodeStatus",
        "socialInboxMigrationStatus",
        "trustGraphMigrationStatus",
        "supportBundleRedactionStatus",
        "rollbackStatus",
        "rawDataIncluded",
        "strictPreviousSummaryRequired",
    )
    compact: dict[str, Any] = {
        "status": compact_status(scenario.get("status", "missing")),
        "evidenceId": "multi-node-beta.upgrade-drill",
    }
    for field in fields:
        if field in evidence:
            compact[field] = evidence[field]
    for field in ("previousSummaryValidationErrors", "currentProductionBetaValidationErrors"):
        compact[field] = compact_public_text_list(evidence.get(field), f"upgradeDrill.{field}")
    return compact


def compact_for_release(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": compact_status(summary.get("status", "missing")),
        "promotionReady": bool(summary.get("promotionReady")),
        "mode": compact_mode(summary.get("mode", "missing")),
        "durationProfile": compact_duration_profile(summary.get("durationProfile", "missing")),
        "scenarioStatuses": scenario_statuses(summary),
        "previousCandidateUpgrade": compact_previous_candidate_upgrade(summary),
        "blockers": compact_public_text_list(summary.get("blockers"), "blockers"),
        "warnings": compact_public_text_list(summary.get("warnings"), "warnings"),
        "redaction": compact_redaction(summary.get("redaction")),
    }


def run_plan(args: argparse.Namespace) -> int:
    try:
        config = validate_config(load_config(args.config), override_mode=args.mode, strict=args.strict)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc
    plan = render_plan(config)
    if args.out:
        write_json(args.out, plan)
    else:
        print(stable_json(plan), end="")
    return 0


def run_soak(args: argparse.Namespace) -> int:
    try:
        config = validate_config(load_config(args.config), override_mode=args.mode, strict=args.strict)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc
    out_dir = args.out_dir
    summary = build_summary(
        config,
        out_dir=out_dir,
        require_live=args.require_live,
        require_all_scenarios=args.require_all_scenarios,
        strict=args.strict,
        base_dir=(args.config.parent if args.config else Path.cwd()),
    )
    report = render_report(summary)
    write_json(out_dir / SUMMARY_FILE_NAME, summary)
    write_json(out_dir / COMPAT_SUMMARY_FILE_NAME, summary)
    write_text(out_dir / REPORT_FILE_NAME, report)
    if args.strict:
        return 1 if validate_summary(summary, strict=True) else 0
    return 1 if summary["status"] == "fail" else 0


def run_verify(args: argparse.Namespace) -> int:
    summary = read_json(args.summary)
    errors = validate_summary(summary, strict=args.strict)
    if errors:
        for error in errors:
            print(f"multi-node beta soak verify failed: {error}")
        return 1
    print("multi-node beta soak verify passed")
    return 0


def run_previous_summary(args: argparse.Namespace) -> int:
    release_summary = read_json(args.release_certification_summary)
    production_summary = read_json(args.production_beta_summary)
    if release_summary is None:
        print("release certification summary is missing or malformed")
        return 1
    if production_summary is None:
        print("production beta summary is missing or malformed")
        return 1
    source_errors = previous_candidate_source_summary_errors(release_summary, production_summary)
    if source_errors:
        for error in source_errors:
            print(error)
        return 1
    summary = build_previous_candidate_summary(
        release_summary,
        production_summary,
        release_certification_digest=sha256_path(args.release_certification_summary),
        production_beta_digest=sha256_path(args.production_beta_summary),
        generated_at=args.generated_at or utc_now_timestamp(),
    )
    errors = validate_previous_beta_candidate_summary(summary)
    if errors:
        for error in errors:
            print(error)
        return 1
    write_json(args.out, summary)
    report_path = args.report or args.out.with_suffix(".md")
    write_text(report_path, render_previous_candidate_report(summary))
    return 0


def run_verify_previous_summary(args: argparse.Namespace) -> int:
    summary = read_json(args.summary)
    errors = validate_previous_beta_candidate_summary(
        summary,
        production=args.strict,
        max_age_days=args.max_age_days,
    )
    if args.report:
        write_text(args.report, render_previous_candidate_report(summary or {}, errors))
    if errors:
        for error in errors:
            print(error)
        return 1
    print("previous beta candidate summary valid")
    return 0


def run_previous_summary_schema(args: argparse.Namespace) -> int:
    schema = previous_candidate_summary_schema()
    if args.out:
        write_json(args.out, schema)
    else:
        print(stable_json(schema), end="")
    return 0


def run_self_test() -> None:
    fixture = fixture_path()
    config = validate_config(load_config(fixture if fixture.is_file() else None))
    previous_fixture = read_json(previous_candidate_fixture_path())
    assert previous_fixture is not None, previous_candidate_fixture_path()
    assert validate_previous_beta_candidate_summary(previous_fixture) == [], previous_fixture
    public_previous_fixture = json.loads(json.dumps(previous_fixture, sort_keys=True))
    public_previous_fixture["source"]["artifactBaseUri"] = "https://downloads.crypta.network/production-beta/269"
    assert validate_previous_beta_candidate_summary(public_previous_fixture, production=True) == [], (
        public_previous_fixture
    )
    strict_fixture_errors = validate_previous_beta_candidate_summary(previous_fixture, production=True)
    assert any(".invalid host" in error for error in strict_fixture_errors), strict_fixture_errors
    for private_artifact_uri in (
        "https://localhost./production-beta/269",
        "https://127.1/production-beta/269",
        "https://10.0.0.5/production-beta/269",
        "https://192.168.1/production-beta/269",
        "https://[::ffff:127.0.0.1]/production-beta/269",
        "https://artifacts.localdomain/production-beta/269",
    ):
        private_artifact_fixture = json.loads(json.dumps(previous_fixture, sort_keys=True))
        private_artifact_fixture["source"]["artifactBaseUri"] = private_artifact_uri
        private_artifact_errors = validate_previous_beta_candidate_summary(
            private_artifact_fixture,
            production=True,
        )
        assert any("public HTTPS" in error for error in private_artifact_errors), (
            private_artifact_uri,
            private_artifact_errors,
        )
    unsupported_secret_key = "privateInsertUri=USK@AQECAAEPRIVATEINSERTKEY,fixture/name/1"
    unsupported_secret_previous = json.loads(json.dumps(previous_fixture, sort_keys=True))
    unsupported_secret_previous[unsupported_secret_key] = "redacted"
    unsupported_secret_errors = validate_previous_beta_candidate_summary(unsupported_secret_previous)
    unsupported_secret_text = "\n".join(unsupported_secret_errors)
    assert "contains 1 unsupported field" in unsupported_secret_text, unsupported_secret_errors
    assert unsupported_secret_key not in unsupported_secret_text, unsupported_secret_errors
    assert "AQECAAEPRIVATEINSERTKEY" not in unsupported_secret_text, unsupported_secret_errors
    schema = previous_candidate_summary_schema()
    schema_properties = schema["properties"]
    for field in ("catalog", "platformApi", "appData", "trustGraph", "socialInbox", "supportBundle", "redaction"):
        assert "properties" in schema_properties[field], (field, schema_properties[field])
    assert "properties" in schema_properties["firstPartyApps"]["items"], schema_properties["firstPartyApps"]
    assert "properties" in schema_properties["appData"]["properties"]["migrationCoverage"]["items"], (
        schema_properties["appData"]
    )
    previous_fixture_missing_app = json.loads(json.dumps(previous_fixture, sort_keys=True))
    previous_fixture_missing_app["firstPartyApps"] = [
        app
        for app in previous_fixture_missing_app["firstPartyApps"]
        if app.get("appId") != "social-inbox"
    ]
    assert any(
        "firstPartyApps missing required apps" in error
        for error in validate_previous_beta_candidate_summary(previous_fixture_missing_app)
    ), previous_fixture_missing_app
    previous_fixture_not_ready = json.loads(json.dumps(previous_fixture, sort_keys=True))
    previous_fixture_not_ready["promotionReady"] = False
    assert "previous candidate summary promotionReady must be true" in (
        validate_previous_beta_candidate_summary(previous_fixture_not_ready)
    ), previous_fixture_not_ready
    for field, value, expected_kind in (
        ("rawAppData", "rawAppDataValue=fixture-raw-app-data", "raw-app-data"),
        ("rawSocialMessage", "rawMessageBody=fixture-raw-social-message", "raw-social-message"),
        ("rawTrustStatement", "rawTrustStatement=fixture-raw-trust-statement", "raw-trust-statement"),
        ("privateInsertUri", "privateInsertUri=USK@AQECAAEPRIVATEINSERTKEY,fixture/name/1", "private-insert-uri"),
        ("token", "CRYPTAD_APP_TOKEN=abcdefghijklmnop", "app-or-session-token"),
        (
            "privateKey",
            "-----BEGIN PRIVATE KEY-----\nfixture-private-key\n-----END PRIVATE KEY-----",
            "private-key",
        ),
    ):
        unsafe_previous = json.loads(json.dumps(previous_fixture, sort_keys=True))
        unsafe_previous[field] = value
        unsafe_errors = validate_previous_beta_candidate_summary(unsafe_previous)
        assert any(expected_kind in error for error in unsafe_errors), (expected_kind, unsafe_errors)
    disabled_redaction_config = json.loads(json.dumps(config, sort_keys=True))
    disabled_redaction_config["redaction"]["failOnTokens"] = False
    try:
        validate_config(disabled_redaction_config)
    except ConfigError as exc:
        assert "redaction.failOnTokens must be true" in str(exc), exc
    else:
        raise AssertionError("disabled redaction config was accepted")
    with tempfile.TemporaryDirectory(prefix="cryptad-multi-node-beta-soak-") as temp_name:
        out_dir = Path(temp_name) / "out"
        summary = build_summary(config, out_dir=out_dir, base_dir=fixture.parent)
        report = render_report(summary)
        assert summary["kind"] == SUMMARY_KIND, summary
        assert summary["status"] == "pass", summary
        assert summary["promotionReady"] is True, summary
        assert summary["redaction"]["status"] == "pass", summary
        assert scenario_statuses(summary)["upgrade-from-previous-candidate"] == "pass", summary
        write_json(out_dir / SUMMARY_FILE_NAME, summary)
        write_text(out_dir / REPORT_FILE_NAME, report)
        assert validate_summary(read_json(out_dir / SUMMARY_FILE_NAME)) == [], summary
        path_plan_config = json.loads(json.dumps(config, sort_keys=True))
        path_plan_config["previousCandidate"]["summaryPath"] = "/srv/runner/work/cryptad/previous-summary.json"
        path_plan_current = path_plan_config["currentCandidate"]
        path_plan_current["productionBetaSummaryPath"] = "/home/runner/work/cryptad/current-summary.json"
        path_plan = render_plan(validate_config(path_plan_config))
        assert path_plan["previousCandidate"] == {
            "version": "269",
            "catalogChannel": "stable",
            "summaryConfigured": True,
        }, path_plan
        assert path_plan["currentCandidate"] == {
            "version": "current-beta",
            "catalogChannel": "stable",
            "productionBetaSummaryConfigured": True,
        }, path_plan
        path_plan_text = stable_json(path_plan)
        assert "summaryPath" not in path_plan_text, path_plan_text
        assert "productionBetaSummaryPath" not in path_plan_text, path_plan_text
        assert "/srv/runner/work" not in path_plan_text, path_plan_text
        assert "/home/runner/work" not in path_plan_text, path_plan_text
        assert scan_redaction_payload(path_plan) == [], path_plan

        unsafe_catalog_config = json.loads(json.dumps(config, sort_keys=True))
        unsafe_catalog_config["nodes"][0]["catalogChannels"] = ["stable", "nightly"]
        unsafe_catalog_summary = build_summary(unsafe_catalog_config, out_dir=out_dir, base_dir=fixture.parent)
        unsafe_catalog_result = scenario_map(unsafe_catalog_summary)["catalog-channel-update"]
        assert unsafe_catalog_result["status"] == "fail", unsafe_catalog_result
        assert unsafe_catalog_result["evidence"]["stableOnlyNodeCount"] == 1, unsafe_catalog_result
        assert unsafe_catalog_result["evidence"]["stableNodesBlockBetaAndNightly"] is False, unsafe_catalog_result
        assert unsafe_catalog_result["evidence"]["nodesWithBlockedCatalogChannels"] == [
            {
                "nodeId": "node-a",
                "catalogChannels": ["stable", "nightly"],
                "blockedCatalogChannels": ["nightly"],
            }
        ], unsafe_catalog_result
        assert unsafe_catalog_result["evidence"]["nightlyCandidatesBlocked"] is False, unsafe_catalog_result

        deprecated_only_catalog_config = json.loads(json.dumps(config, sort_keys=True))
        deprecated_only_catalog_config["nodes"][0]["catalogChannels"] = ["stable"]
        deprecated_only_catalog_config["nodes"][2]["catalogChannels"] = ["deprecated"]
        deprecated_only_catalog_summary = build_summary(
            deprecated_only_catalog_config,
            out_dir=out_dir,
            base_dir=fixture.parent,
        )
        deprecated_only_catalog_result = scenario_map(deprecated_only_catalog_summary)["catalog-channel-update"]
        assert deprecated_only_catalog_result["status"] == "fail", deprecated_only_catalog_result
        assert deprecated_only_catalog_result["evidence"]["stableNodesBlockBetaAndNightly"] is False, (
            deprecated_only_catalog_result
        )
        assert deprecated_only_catalog_result["evidence"]["deprecatedCandidatesBlocked"] is False, (
            deprecated_only_catalog_result
        )
        assert deprecated_only_catalog_result["evidence"]["nodesWithBlockedCatalogChannels"] == [
            {
                "nodeId": "node-c",
                "catalogChannels": ["deprecated"],
                "blockedCatalogChannels": ["deprecated"],
            }
        ], deprecated_only_catalog_result

        for field in (
            "stableNodesBlockBetaAndNightly",
            "betaNodesOptInExplicitly",
            "nightlyCandidatesBlocked",
            "deprecatedCandidatesBlocked",
            "denylistedCandidatesBlocked",
        ):
            contradictory_catalog_summary = json.loads(json.dumps(summary, sort_keys=True))
            contradictory_catalog_evidence = scenario_map(contradictory_catalog_summary)[
                "catalog-channel-update"
            ]["evidence"]
            contradictory_catalog_evidence[field] = False
            assert f"scenario catalog-channel-update pass requires {field}" in validate_summary(
                contradictory_catalog_summary
            ), (field, contradictory_catalog_summary)
        contradictory_catalog_summary = json.loads(json.dumps(summary, sort_keys=True))
        contradictory_catalog_evidence = scenario_map(contradictory_catalog_summary)["catalog-channel-update"][
            "evidence"
        ]
        contradictory_catalog_evidence["nodesWithBlockedCatalogChannels"] = [
            {
                "nodeId": "node-a",
                "catalogChannels": ["stable", "nightly"],
                "blockedCatalogChannels": ["nightly"],
            }
        ]
        assert "scenario catalog-channel-update pass requires empty nodesWithBlockedCatalogChannels" in (
            validate_summary(contradictory_catalog_summary)
        ), contradictory_catalog_summary

        strict_config = json.loads(json.dumps(config, sort_keys=True))
        strict_config["strict"]["requirePreviousSummary"] = True
        strict_config["previousCandidate"]["summaryPath"] = ""
        strict_summary = build_summary(strict_config, out_dir=out_dir, strict=True, base_dir=fixture.parent)
        assert strict_summary["status"] == "fail", strict_summary
        assert validate_summary(strict_summary, strict=True), strict_summary

        invalid_strict_config = json.loads(json.dumps(config, sort_keys=True))
        invalid_strict_config["strict"]["requirePreviousSummary"] = "false"
        try:
            validate_config(invalid_strict_config)
        except ConfigError as exc:
            assert "strict.requirePreviousSummary must be true or false" in str(exc), exc
        else:
            raise AssertionError("strict.requirePreviousSummary accepted a non-boolean value")

        unsafe_live_plan_config = json.loads(json.dumps(config, sort_keys=True))
        unsafe_live_plan_config["nodes"][0]["baseUrl"] = "http://example.invalid:9481/"
        try:
            validate_config(unsafe_live_plan_config, override_mode="live")
        except ConfigError as exc:
            assert "nodes[0].baseUrl must be localhost-only" in str(exc), exc
        else:
            raise AssertionError("live topology accepted an unsafe baseUrl")

        credential_live_plan_config = json.loads(json.dumps(config, sort_keys=True))
        credential_live_plan_config["nodes"][0]["baseUrl"] = "http://operator@127.0.0.1:9481/"
        try:
            validate_config(credential_live_plan_config, override_mode="live")
        except ConfigError as exc:
            assert "nodes[0].baseUrl must be localhost-only" in str(exc), exc
        else:
            raise AssertionError("live topology accepted a credential-bearing baseUrl")

        invalid_previous_config = json.loads(json.dumps(config, sort_keys=True))
        write_json(out_dir / "previous-empty.json", {})
        invalid_previous_config["previousCandidate"]["summaryPath"] = "previous-empty.json"
        invalid_previous_summary = build_summary(invalid_previous_config, out_dir=out_dir, base_dir=out_dir)
        invalid_upgrade = scenario_map(invalid_previous_summary)["upgrade-from-previous-candidate"]
        assert invalid_upgrade["status"] == "fail", invalid_previous_summary
        assert "schemaVersion" in " ".join(invalid_upgrade["evidence"]["previousSummaryValidationErrors"]), (
            invalid_upgrade
        )

        failed_previous_config = json.loads(json.dumps(config, sort_keys=True))
        write_json(out_dir / "previous-failed.json", {"schemaVersion": SCHEMA_VERSION, "status": "fail"})
        failed_previous_config["previousCandidate"]["summaryPath"] = "previous-failed.json"
        failed_previous_summary = build_summary(failed_previous_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        failed_upgrade = scenario_map(failed_previous_summary)["upgrade-from-previous-candidate"]
        assert failed_previous_summary["status"] == "fail", failed_previous_summary
        assert failed_upgrade["status"] == "fail", failed_upgrade
        assert any("status is fail" in error for error in failed_upgrade["evidence"]["previousSummaryValidationErrors"]), (
            failed_upgrade
        )

        valid_previous_config = json.loads(json.dumps(config, sort_keys=True))
        valid_previous_config["previousCandidate"]["version"] = "previous-beta"
        previous_source_metadata = {
            field: clone_json_value(previous_fixture[field])
            for field in PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS
        }
        for app in previous_source_metadata["firstPartyApps"]:
            app["version"] = "previous-beta"
        valid_previous_candidate = build_previous_candidate_summary(
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "release-certification",
                "version": "previous-beta",
                "status": "pass",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-previous-git"},
                "evidence": [{"id": "self-test.previous", "status": "pass"}],
            },
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "production-beta-release",
                "version": "previous-beta",
                "status": "pass",
                "promotionReady": True,
                "artifactBaseUri": "https://downloads.crypta.invalid/production-beta/previous-beta",
                **previous_source_metadata,
            },
            release_certification_digest=synthetic_full_digest("self-test-release-certification"),
            production_beta_digest=synthetic_full_digest("self-test-production-beta"),
        )
        write_json(
            out_dir / "previous-valid.json",
            valid_previous_candidate,
        )
        assert validate_previous_beta_candidate_summary(valid_previous_candidate) == [], valid_previous_candidate
        schema_mismatched_status_candidate = clone_json_value(valid_previous_candidate)
        schema_mismatched_status_candidate["status"] = "success"
        schema_mismatched_status_candidate["catalog"]["mirrorHealthStatus"] = "success"
        schema_mismatched_status_candidate["appData"]["restoreDrillStatus"] = "success"
        schema_mismatched_status_candidate["appData"]["migrationCoverage"][0]["status"] = "success"
        schema_mismatched_status_candidate["supportBundle"]["redactionStatus"] = "success"
        schema_mismatched_status_candidate["redaction"]["status"] = "success"
        schema_status_errors = validate_previous_beta_candidate_summary(schema_mismatched_status_candidate)
        for expected_error in (
            "previous candidate summary status must be pass",
            "previous candidate summary catalog.mirrorHealthStatus must be pass",
            "previous candidate summary appData.restoreDrillStatus must be pass",
            "previous candidate summary appData.migrationCoverage[0].status must be pass",
            "previous candidate summary supportBundle.redactionStatus must be pass",
            "previous candidate summary redaction.status must be pass",
        ):
            assert expected_error in schema_status_errors, schema_status_errors
        mismatched_previous_version_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        mismatched_previous_version_config["previousCandidate"]["summaryPath"] = "previous-valid.json"
        mismatched_previous_version_config["previousCandidate"]["version"] = "wrong-version"
        mismatched_previous_version_summary = build_summary(
            mismatched_previous_version_config,
            out_dir=out_dir,
            strict=True,
            base_dir=out_dir,
        )
        mismatched_previous_version_upgrade = scenario_map(mismatched_previous_version_summary)[
            "upgrade-from-previous-candidate"
        ]
        assert mismatched_previous_version_summary["status"] == "fail", mismatched_previous_version_summary
        assert mismatched_previous_version_upgrade["status"] == "fail", mismatched_previous_version_upgrade
        assert any(
            "does not match configured previousCandidate.version" in error
            for error in mismatched_previous_version_upgrade["evidence"]["previousSummaryValidationErrors"]
        ), mismatched_previous_version_upgrade
        previous_summary_cli_out = out_dir / "previous-cli-summary.json"
        release_summary_cli_in = out_dir / "previous-cli-release-certification.json"
        production_summary_cli_in = out_dir / "previous-cli-production-beta.json"
        previous_cli_source_metadata = {
            field: clone_json_value(previous_fixture[field])
            for field in PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS
        }
        for app in previous_cli_source_metadata["firstPartyApps"]:
            app["version"] = "previous-cli-beta"
        write_json(
            release_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "release-certification",
                "version": "previous-cli-beta",
                "status": "warn",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-previous-cli-git"},
                "evidence": [{"id": "self-test.previous-cli", "status": "pass"}],
            },
        )
        write_json(
            production_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "production-beta-release",
                "version": "previous-cli-beta",
                "status": "pass",
                "promotionReady": True,
                "artifactBaseUri": "https://downloads.crypta.network/production-beta/previous-cli-beta",
                **previous_cli_source_metadata,
            },
        )
        assert (
            run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=previous_summary_cli_out,
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
            == 0
        )
        mismatched_identity_release_summary_cli_in = (
            out_dir / "previous-cli-release-certification-identity-mismatch.json"
        )
        write_json(
            mismatched_identity_release_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "release-certification",
                "version": "different-previous-cli-beta",
                "status": "pass",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-previous-cli-git"},
                "evidence": [{"id": "self-test.previous-cli", "status": "pass"}],
            },
        )
        identity_mismatch_stdout = io.StringIO()
        with contextlib.redirect_stdout(identity_mismatch_stdout):
            identity_mismatch_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=mismatched_identity_release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=out_dir / "previous-cli-identity-mismatch-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert identity_mismatch_exit == 1
        assert "previous candidate source version differs" in identity_mismatch_stdout.getvalue(), (
            identity_mismatch_stdout.getvalue()
        )
        minimal_production_summary_cli_in = out_dir / "previous-cli-production-beta-minimal.json"
        write_json(
            minimal_production_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "production-beta-release",
                "version": "previous-cli-beta",
                "status": "pass",
                "promotionReady": True,
                "artifactBaseUri": "https://downloads.crypta.invalid/production-beta/previous-cli-beta",
            },
        )
        minimal_stdout = io.StringIO()
        with contextlib.redirect_stdout(minimal_stdout):
            minimal_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=release_summary_cli_in,
                    production_beta_summary=minimal_production_summary_cli_in,
                    out=out_dir / "previous-cli-minimal-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert minimal_exit == 1
        assert "previous candidate source metadata catalog is missing" in minimal_stdout.getvalue(), (
            minimal_stdout.getvalue()
        )
        previous_candidate_as_release_summary_cli_in = (
            out_dir / "previous-cli-release-certification-is-previous-candidate.json"
        )
        write_json(previous_candidate_as_release_summary_cli_in, valid_previous_candidate)
        previous_candidate_source_stdout = io.StringIO()
        with contextlib.redirect_stdout(previous_candidate_source_stdout):
            previous_candidate_source_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=previous_candidate_as_release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=out_dir / "previous-cli-previous-candidate-as-release-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert previous_candidate_source_exit == 1
        assert "not a previous beta candidate summary" in previous_candidate_source_stdout.getvalue(), (
            previous_candidate_source_stdout.getvalue()
        )
        previous_candidate_as_production_summary_cli_in = (
            out_dir / "previous-cli-production-beta-is-previous-candidate.json"
        )
        write_json(previous_candidate_as_production_summary_cli_in, valid_previous_candidate)
        previous_candidate_production_stdout = io.StringIO()
        with contextlib.redirect_stdout(previous_candidate_production_stdout):
            previous_candidate_production_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=release_summary_cli_in,
                    production_beta_summary=previous_candidate_as_production_summary_cli_in,
                    out=out_dir / "previous-cli-previous-candidate-as-production-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert previous_candidate_production_exit == 1
        assert "production beta summary must be a production-beta-release summary" in (
            previous_candidate_production_stdout.getvalue()
        ), previous_candidate_production_stdout.getvalue()
        unrelated_release_summary_cli_in = out_dir / "previous-cli-release-certification-unrelated.json"
        write_json(
            unrelated_release_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "unrelated-release-tool",
                "version": "previous-cli-beta",
                "status": "pass",
                "releaseCandidatePassed": True,
                "evidence": [{"id": "self-test.previous-cli", "status": "pass"}],
                **previous_cli_source_metadata,
            },
        )
        unrelated_source_stdout = io.StringIO()
        with contextlib.redirect_stdout(unrelated_source_stdout):
            unrelated_source_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=unrelated_release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=out_dir / "previous-cli-unrelated-release-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert unrelated_source_exit == 1
        assert "tool must be release-certification" in unrelated_source_stdout.getvalue(), (
            unrelated_source_stdout.getvalue()
        )
        mismatched_release_summary_cli_in = out_dir / "previous-cli-release-certification-metadata-mismatch.json"
        mismatched_release_metadata = {
            field: clone_json_value(previous_cli_source_metadata[field])
            for field in PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS
        }
        mismatched_release_metadata["catalog"]["stableChannelEdition"] = 999
        write_json(
            mismatched_release_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "release-certification",
                "version": "previous-cli-beta",
                "status": "pass",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-previous-cli-git"},
                "evidence": [{"id": "self-test.previous-cli", "status": "pass"}],
                **mismatched_release_metadata,
            },
        )
        mismatch_stdout = io.StringIO()
        with contextlib.redirect_stdout(mismatch_stdout):
            mismatch_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=mismatched_release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=out_dir / "previous-cli-mismatched-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert mismatch_exit == 1
        assert "previous candidate source metadata catalog differs" in mismatch_stdout.getvalue(), (
            mismatch_stdout.getvalue()
        )
        assert (
            run_verify_previous_summary(
                argparse.Namespace(
                    summary=previous_summary_cli_out,
                    report=out_dir / "previous-cli-summary.md",
                    strict=True,
                    max_age_days=None,
                )
            )
            == 0
        )
        failing_production_summary_cli_in = out_dir / "previous-cli-production-beta-failing.json"
        write_json(
            failing_production_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "production-beta-release",
                "version": "previous-cli-beta",
                "status": "fail",
                "promotionReady": False,
                "artifactBaseUri": "https://downloads.crypta.invalid/production-beta/previous-cli-beta",
            },
        )
        with contextlib.redirect_stdout(io.StringIO()):
            failing_production_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=release_summary_cli_in,
                    production_beta_summary=failing_production_summary_cli_in,
                    out=out_dir / "previous-cli-failing-production-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert failing_production_exit == 1
        failing_release_summary_cli_in = out_dir / "previous-cli-release-certification-failing.json"
        write_json(
            failing_release_summary_cli_in,
            {
                "schemaVersion": SCHEMA_VERSION,
                "tool": "release-certification",
                "version": "previous-cli-beta",
                "status": "fail",
                "releaseCandidatePassed": False,
                "metadata": {"gitCommit": "self-test-previous-cli-git"},
                "evidence": [{"id": "self-test.previous-cli", "status": "fail"}],
            },
        )
        with contextlib.redirect_stdout(io.StringIO()):
            failing_release_exit = run_previous_summary(
                argparse.Namespace(
                    release_certification_summary=failing_release_summary_cli_in,
                    production_beta_summary=production_summary_cli_in,
                    out=out_dir / "previous-cli-failing-release-summary.json",
                    report=None,
                    generated_at=DETERMINISTIC_GENERATED_AT,
                )
            )
        assert failing_release_exit == 1
        failing_source_previous_candidate = build_previous_candidate_summary(
            read_json(failing_release_summary_cli_in),
            read_json(production_summary_cli_in),
            release_certification_digest=synthetic_full_digest("self-test-failing-release"),
            production_beta_digest=synthetic_full_digest("self-test-production-beta"),
        )
        assert failing_source_previous_candidate["status"] == "fail", failing_source_previous_candidate
        assert failing_source_previous_candidate["promotionReady"] is False, failing_source_previous_candidate
        valid_previous_config["previousCandidate"]["summaryPath"] = "previous-valid.json"
        valid_previous_summary = build_summary(valid_previous_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        valid_upgrade = scenario_map(valid_previous_summary)["upgrade-from-previous-candidate"]
        assert valid_upgrade["status"] == "pass", valid_previous_summary
        assert valid_upgrade["evidence"]["previousSummaryValid"] is True, valid_upgrade
        assert valid_upgrade["evidence"]["supportBundleAfterFailedUpgrade"]["redactionStatus"] == "pass", (
            valid_upgrade
        )

        warning_only_strict_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        for node in warning_only_strict_config["nodes"]:
            node["catalogChannels"] = ["stable"]
        warning_only_config_path = out_dir / "warning-only-strict-config.json"
        warning_only_out_dir = out_dir / "warning-only-strict-run"
        write_json(warning_only_config_path, warning_only_strict_config)
        warning_only_exit = run_soak(
            argparse.Namespace(
                config=warning_only_config_path,
                out_dir=warning_only_out_dir,
                mode=None,
                require_live=False,
                require_all_scenarios=False,
                strict=True,
            )
        )
        warning_only_summary = read_json(warning_only_out_dir / SUMMARY_FILE_NAME)
        assert warning_only_exit == 1, warning_only_summary
        assert isinstance(warning_only_summary, dict), warning_only_summary
        assert warning_only_summary["status"] == "warn", warning_only_summary
        assert warning_only_summary["promotionReady"] is False, warning_only_summary
        assert "strict summary status must be pass" in validate_summary(warning_only_summary, strict=True), (
            warning_only_summary
        )

        missing_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        missing_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-missing.json"
        missing_current_summary = build_summary(missing_current_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        missing_current_upgrade = scenario_map(missing_current_summary)["upgrade-from-previous-candidate"]
        assert missing_current_summary["status"] == "fail", missing_current_summary
        assert missing_current_upgrade["status"] == "fail", missing_current_upgrade
        assert any(
            "missing or malformed" in error
            for error in missing_current_upgrade["evidence"]["currentProductionBetaValidationErrors"]
        ), missing_current_upgrade

        malformed_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        write_json(out_dir / "current-empty.json", {})
        malformed_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-empty.json"
        malformed_current_summary = build_summary(malformed_current_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        malformed_current_upgrade = scenario_map(malformed_current_summary)["upgrade-from-previous-candidate"]
        assert malformed_current_upgrade["status"] == "fail", malformed_current_upgrade
        assert "schemaVersion" in " ".join(
            malformed_current_upgrade["evidence"]["currentProductionBetaValidationErrors"]
        ), malformed_current_upgrade

        failed_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        write_json(out_dir / "current-failed.json", {"schemaVersion": SCHEMA_VERSION, "status": "fail"})
        failed_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-failed.json"
        failed_current_summary = build_summary(failed_current_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        failed_current_upgrade = scenario_map(failed_current_summary)["upgrade-from-previous-candidate"]
        assert failed_current_summary["status"] == "fail", failed_current_summary
        assert failed_current_upgrade["status"] == "fail", failed_current_upgrade
        assert any(
            "status is fail" in error
            for error in failed_current_upgrade["evidence"]["currentProductionBetaValidationErrors"]
        ), failed_current_upgrade

        no_catalog_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        write_json(
            out_dir / "current-no-catalog.json",
            {"schemaVersion": SCHEMA_VERSION, "status": "pass", "promotionReady": True},
        )
        no_catalog_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-no-catalog.json"
        no_catalog_current_summary = build_summary(
            no_catalog_current_config,
            out_dir=out_dir,
            strict=True,
            base_dir=out_dir,
        )
        no_catalog_current_upgrade = scenario_map(no_catalog_current_summary)["upgrade-from-previous-candidate"]
        assert no_catalog_current_summary["status"] == "fail", no_catalog_current_summary
        assert no_catalog_current_upgrade["evidence"]["currentCatalogEdition"] is None, (
            no_catalog_current_upgrade
        )
        assert any(
            "catalog metadata is missing" in error
            for error in no_catalog_current_upgrade["evidence"]["currentProductionBetaValidationErrors"]
        ), no_catalog_current_upgrade

        valid_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        write_json(
            out_dir / "current-valid.json",
            {
                "schemaVersion": SCHEMA_VERSION,
                "status": "pass",
                "promotionReady": True,
                "previousCandidateMetadata": {
                    "catalog": {
                        "stableChannelEdition": 100,
                        "betaChannelEdition": 200,
                    },
                },
            },
        )
        valid_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-valid.json"
        valid_current_summary = build_summary(valid_current_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        valid_current_upgrade = scenario_map(valid_current_summary)["upgrade-from-previous-candidate"]
        assert valid_current_upgrade["status"] == "pass", valid_current_summary
        assert valid_current_upgrade["evidence"]["currentProductionBetaSummaryValid"] is True, valid_current_upgrade

        write_json(
            out_dir / "current-channel-editions.json",
            {
                "schemaVersion": SCHEMA_VERSION,
                "status": "pass",
                "promotionReady": True,
                "previousCandidateMetadata": {
                    "catalog": {
                        "stableChannelEdition": 501,
                        "betaChannelEdition": 777,
                    },
                },
            },
        )
        stable_channel_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        stable_channel_config["currentCandidate"]["productionBetaSummaryPath"] = "current-channel-editions.json"
        stable_channel_config["currentCandidate"]["catalogChannel"] = "stable"
        stable_channel_summary = build_summary(stable_channel_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        stable_channel_upgrade = scenario_map(stable_channel_summary)["upgrade-from-previous-candidate"]
        assert stable_channel_upgrade["evidence"]["currentCatalogEdition"] == 501, stable_channel_upgrade

        beta_channel_config = json.loads(json.dumps(stable_channel_config, sort_keys=True))
        beta_channel_config["currentCandidate"]["catalogChannel"] = "beta"
        beta_channel_summary = build_summary(beta_channel_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        beta_channel_upgrade = scenario_map(beta_channel_summary)["upgrade-from-previous-candidate"]
        assert beta_channel_upgrade["evidence"]["currentCatalogEdition"] == 777, beta_channel_upgrade

        pass_with_warn_scenario_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        scenario_map(pass_with_warn_scenario_summary)["backup-restore"]["status"] = "warn"
        pass_with_warn_scenario_summary["scenarioStatuses"]["backup-restore"] = "warn"
        pass_with_warn_scenario_summary["status"] = "pass"
        pass_with_warn_scenario_summary["promotionReady"] = True
        pass_with_warn_scenario_summary["warnings"] = []
        assert "summary status must not be pass when scenarios are not pass" in validate_summary(
            pass_with_warn_scenario_summary
        ), pass_with_warn_scenario_summary

        warn_with_fail_scenario_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        scenario_map(warn_with_fail_scenario_summary)["backup-restore"]["status"] = "fail"
        warn_with_fail_scenario_summary["scenarioStatuses"]["backup-restore"] = "fail"
        warn_with_fail_scenario_summary["status"] = "warn"
        warn_with_fail_scenario_summary["promotionReady"] = False
        warn_with_fail_scenario_summary["blockers"] = []
        assert "summary status must be fail when scenarios fail" in validate_summary(
            warn_with_fail_scenario_summary
        ), warn_with_fail_scenario_summary

        pass_with_warn_redaction_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        pass_with_warn_redaction_summary["redaction"]["status"] = "warn"
        pass_with_warn_redaction_summary["status"] = "pass"
        pass_with_warn_redaction_summary["promotionReady"] = True
        pass_with_warn_redaction_summary["warnings"] = []
        assert "summary status must not be pass when redaction is not pass" in validate_summary(
            pass_with_warn_redaction_summary
        ), pass_with_warn_redaction_summary

        warn_with_fail_redaction_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        warn_with_fail_redaction_summary["redaction"]["status"] = "fail"
        warn_with_fail_redaction_summary["status"] = "warn"
        warn_with_fail_redaction_summary["promotionReady"] = False
        warn_with_fail_redaction_summary["blockers"] = []
        assert "summary status must be fail when redaction fails" in validate_summary(
            warn_with_fail_redaction_summary
        ), warn_with_fail_redaction_summary
        missing_previous_attached_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        missing_previous_attached_summary["previousCandidate"]["summaryProvided"] = False
        missing_previous_upgrade = scenario_map(missing_previous_attached_summary)["upgrade-from-previous-candidate"]
        missing_previous_upgrade["status"] = "pass"
        missing_previous_evidence = missing_previous_upgrade["evidence"]
        missing_previous_evidence["previousSummaryConfigured"] = False
        missing_previous_evidence["previousSummaryProvided"] = False
        missing_previous_evidence["previousSummaryValid"] = False
        missing_previous_evidence["previousSummaryValidationErrors"] = []
        missing_previous_errors = validate_summary(missing_previous_attached_summary)
        assert "scenario upgrade-from-previous-candidate pass requires previousSummaryConfigured" in (
            missing_previous_errors
        ), missing_previous_errors
        assert "scenario upgrade-from-previous-candidate pass requires previousSummaryProvided" in (
            missing_previous_errors
        ), missing_previous_errors
        assert "scenario upgrade-from-previous-candidate pass requires previousSummaryValid" in (
            missing_previous_errors
        ), missing_previous_errors

        invalid_current_attached_summary = json.loads(json.dumps(valid_current_summary, sort_keys=True))
        invalid_current_upgrade = scenario_map(invalid_current_attached_summary)["upgrade-from-previous-candidate"]
        invalid_current_upgrade["status"] = "pass"
        invalid_current_evidence = invalid_current_upgrade["evidence"]
        invalid_current_evidence["currentProductionBetaSummaryConfigured"] = True
        invalid_current_evidence["currentProductionBetaSummaryProvided"] = True
        invalid_current_evidence["currentProductionBetaSummaryValid"] = False
        invalid_current_evidence["currentProductionBetaValidationErrors"] = ["fixture current summary invalid"]
        invalid_current_errors = validate_summary(invalid_current_attached_summary)
        assert (
            "scenario upgrade-from-previous-candidate pass requires currentProductionBetaSummaryValid "
            "when configured"
        ) in invalid_current_errors, invalid_current_errors
        assert (
            "scenario upgrade-from-previous-candidate pass requires empty "
            "currentProductionBetaValidationErrors when configured"
        ) in invalid_current_errors, invalid_current_errors

        disabled_config = json.loads(json.dumps(config, sort_keys=True))
        disabled_config["scenarios"]["backupRestore"] = False
        disabled_summary = build_summary(disabled_config, out_dir=out_dir, strict=True, base_dir=fixture.parent)
        assert disabled_summary["status"] == "fail", disabled_summary
        assert "backup-restore failed" in disabled_summary["blockers"], disabled_summary
        required_scenario_summary = build_summary(
            disabled_config,
            out_dir=out_dir,
            require_all_scenarios=True,
            base_dir=fixture.parent,
        )
        assert required_scenario_summary["status"] == "fail", required_scenario_summary
        assert "backup-restore failed" in required_scenario_summary["blockers"], required_scenario_summary
        assert (
            scenario_map(required_scenario_summary)["backup-restore"]["evidence"]["strict"] is True
        ), required_scenario_summary

        live_unsafe_config = json.loads(json.dumps(config, sort_keys=True))
        live_unsafe_config["mode"] = "live"
        live_unsafe_config["nodes"][0]["baseUrl"] = "http://example.invalid:9481/"
        live_unsafe_summary = build_summary(live_unsafe_config, out_dir=out_dir, base_dir=fixture.parent)
        assert live_unsafe_summary["status"] == "fail", live_unsafe_summary
        assert any("unsafe baseUrl" in blocker for blocker in live_unsafe_summary["blockers"]), (
            live_unsafe_summary
        )

        captured_handlers: list[Any] = []

        class OkProbeResponse:
            status = 204

            def __enter__(self) -> "OkProbeResponse":
                return self

            def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
                return False

        class OkProbeOpener:
            def open(self, request: urllib.request.Request, timeout: float = 1.0) -> Any:
                return OkProbeResponse()

        original_build_opener = urllib.request.build_opener

        def recording_build_opener(*handlers: Any) -> OkProbeOpener:
            captured_handlers.extend(handlers)
            return OkProbeOpener()

        urllib.request.build_opener = recording_build_opener
        try:
            assert reachable_local_node("http://127.0.0.1:9481/") is True
        finally:
            urllib.request.build_opener = original_build_opener
        assert any(
            isinstance(handler, urllib.request.ProxyHandler) and getattr(handler, "proxies", None) == {}
            for handler in captured_handlers
        ), captured_handlers
        assert any(isinstance(handler, NoRedirectHandler) for handler in captured_handlers), captured_handlers

        class ForbiddenProbeOpener:
            def open(self, request: urllib.request.Request, timeout: float = 1.0) -> Any:
                raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", hdrs=None, fp=None)

        class RedirectProbeOpener:
            def open(self, request: urllib.request.Request, timeout: float = 1.0) -> Any:
                raise urllib.error.HTTPError(request.full_url, 302, "Found", hdrs=None, fp=None)

        original_probe_opener = localhost_probe_opener
        try:
            globals()["localhost_probe_opener"] = lambda: ForbiddenProbeOpener()
            assert reachable_local_node("http://127.0.0.1:9481/forbidden") is True
            globals()["localhost_probe_opener"] = lambda: RedirectProbeOpener()
            assert reachable_local_node("http://127.0.0.1:9481/redirect") is False
        finally:
            globals()["localhost_probe_opener"] = original_probe_opener

    malformed = {"schemaVersion": 1, "kind": SUMMARY_KIND, "status": "pass"}
    assert validate_summary(malformed), malformed
    minimal_attached_summary = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUMMARY_KIND,
        "generatedAt": DETERMINISTIC_GENERATED_AT,
        "mode": "simulated",
        "durationProfile": "ci-smoke",
        "status": "pass",
        "promotionReady": True,
        "nodes": [{"id": "node-a"}, {"id": "node-b"}],
        "scenarios": [
            {
                "id": scenario_id,
                "status": "pass",
                "summary": "minimal pass",
                "evidence": {"evidenceId": evidence_id},
            }
            for scenario_id, evidence_id in SCENARIO_EVIDENCE_IDS.items()
        ],
        "scenarioStatuses": {scenario_id: "pass" for scenario_id in SCENARIO_EVIDENCE_IDS},
        "blockers": [],
        "warnings": [],
        "redaction": {
            "status": "pass",
            "findings": [],
            "checks": {key: True for key in REDACTION_KEYS},
        },
        "artifacts": {
            "markdownReport": REPORT_FILE_NAME,
            "rawSummary": SUMMARY_FILE_NAME,
        },
    }
    minimal_attached_errors = validate_summary(minimal_attached_summary)
    assert "previousCandidate must be an object" in minimal_attached_errors, minimal_attached_errors
    assert "currentCandidate must be an object" in minimal_attached_errors, minimal_attached_errors
    assert "topology must be an object" in minimal_attached_errors, minimal_attached_errors
    assert "nodes[0].role is invalid" in minimal_attached_errors, minimal_attached_errors
    assert "scenario catalog-channel-update evidence missing stableOnlyNodeCount" in minimal_attached_errors, (
        minimal_attached_errors
    )
    malformed_redaction = json.loads(json.dumps(summary, sort_keys=True))
    malformed_redaction["redaction"] = ["not", "an", "object"]
    assert "redaction must be an object" in validate_summary(malformed_redaction), malformed_redaction
    assert "Redaction: `missing`" in render_report(malformed_redaction)
    assert "strict redaction status must pass" in validate_summary(malformed_redaction, strict=True), (
        malformed_redaction
    )
    malformed_nodes = json.loads(json.dumps(summary, sort_keys=True))
    malformed_nodes["nodes"] = 1
    assert "nodes must include at least two entries" in validate_summary(malformed_nodes), malformed_nodes
    assert "Nodes: `0`" in render_report(malformed_nodes)
    missing_redaction_checks_summary = json.loads(json.dumps(summary, sort_keys=True))
    missing_redaction_checks_summary["redaction"].pop("checks")
    assert any(
        "missing-redaction-checks" in error for error in validate_summary(missing_redaction_checks_summary)
    ), missing_redaction_checks_summary
    disabled_redaction_check_summary = json.loads(json.dumps(summary, sort_keys=True))
    disabled_redaction_check_summary["redaction"]["checks"]["failOnTokens"] = False
    assert any(
        "disabled-redaction-check" in error for error in validate_summary(disabled_redaction_check_summary)
    ), disabled_redaction_check_summary
    malformed_redaction_check_summary = json.loads(json.dumps(summary, sort_keys=True))
    malformed_redaction_check_summary["redaction"]["checks"]["failOnTokens"] = "true"
    assert any(
        "malformed-redaction-check" in error for error in validate_summary(malformed_redaction_check_summary)
    ), malformed_redaction_check_summary
    non_promotable_pass_summary = json.loads(json.dumps(summary, sort_keys=True))
    non_promotable_pass_summary["status"] = "pass"
    non_promotable_pass_summary["promotionReady"] = False
    assert "promotionReady must be true when summary status is pass" in validate_summary(
        non_promotable_pass_summary
    ), non_promotable_pass_summary
    pass_with_blockers_summary = json.loads(json.dumps(summary, sort_keys=True))
    pass_with_blockers_summary["status"] = "pass"
    pass_with_blockers_summary["promotionReady"] = True
    pass_with_blockers_summary["blockers"] = ["fixture blocker"]
    pass_with_blockers_errors = validate_summary(pass_with_blockers_summary)
    assert "summary status must be fail when blockers are present" in pass_with_blockers_errors, (
        pass_with_blockers_errors
    )
    assert "promotionReady must be false when blockers are present" in pass_with_blockers_errors, (
        pass_with_blockers_errors
    )
    pass_with_warnings_summary = json.loads(json.dumps(summary, sort_keys=True))
    pass_with_warnings_summary["status"] = "pass"
    pass_with_warnings_summary["promotionReady"] = True
    pass_with_warnings_summary["warnings"] = ["fixture warning"]
    assert "summary status must not be pass when warnings are present" in validate_summary(
        pass_with_warnings_summary
    ), pass_with_warnings_summary
    malformed_blockers_summary = json.loads(json.dumps(summary, sort_keys=True))
    malformed_blockers_summary["blockers"] = "fixture blocker"
    assert "blockers must be a list" in validate_summary(malformed_blockers_summary), (
        malformed_blockers_summary
    )
    malformed_warnings_summary = json.loads(json.dumps(summary, sort_keys=True))
    malformed_warnings_summary["warnings"] = "fixture warning"
    assert "warnings must be a list" in validate_summary(malformed_warnings_summary), (
        malformed_warnings_summary
    )
    unsafe_safety_summary = json.loads(json.dumps(summary, sort_keys=True))
    unsafe_safety_evidence = scenario_map(unsafe_safety_summary)["support-bundle-drill"]["evidence"]
    unsafe_safety_evidence["privateInsertUrisIncluded"] = True
    unsafe_safety_evidence["tokensIncluded"] = True
    unsafe_safety_evidence["rawContentRedacted"] = False
    unsafe_safety_evidence["rawAppDataIncluded"] = "false"
    unsafe_safety_evidence["redactionScanStatus"] = "fail"
    unsafe_safety_errors = validate_summary(unsafe_safety_summary)
    assert any("forbidden-included-flag" in error for error in unsafe_safety_errors), unsafe_safety_errors
    assert any("missing-redaction-flag" in error for error in unsafe_safety_errors), unsafe_safety_errors
    assert any("malformed-safety-flag" in error for error in unsafe_safety_errors), unsafe_safety_errors
    assert any("redaction-scan-status" in error for error in unsafe_safety_errors), unsafe_safety_errors
    structured_token_summary = json.loads(json.dumps(summary, sort_keys=True))
    structured_token_summary["browserSessionToken"] = "abcdef1234567890"
    assert any(
        "app-or-session-token" in error for error in validate_summary(structured_token_summary)
    ), structured_token_summary
    nested_token_summary = json.loads(json.dumps(summary, sort_keys=True))
    nested_token_summary["evidence"] = {"browserSessionToken": {"value": "abcdef1234567890"}}
    assert any("app-or-session-token" in error for error in validate_summary(nested_token_summary)), (
        nested_token_summary
    )
    structured_form_password_summary = json.loads(json.dumps(summary, sort_keys=True))
    structured_form_password_summary["evidence"] = {"formPassword": "fixture-form-password"}
    assert any(
        "form-password" in error for error in validate_summary(structured_form_password_summary)
    ), structured_form_password_summary
    header_form_password_summary = json.loads(json.dumps(summary, sort_keys=True))
    header_form_password_summary["evidence"] = "X-Crypta-Form-Password: fixture-form-password"
    assert any("form-password" in error for error in validate_summary(header_form_password_summary)), (
        header_form_password_summary
    )
    cli_form_password_summary = json.loads(json.dumps(summary, sort_keys=True))
    cli_form_password_summary["evidence"] = "--form-password fixture-form-password"
    assert any("form-password" in error for error in validate_summary(cli_form_password_summary)), (
        cli_form_password_summary
    )
    form_password_key_summary = json.loads(json.dumps(summary, sort_keys=True))
    form_password_key_summary["evidence"] = {"formPassword=fixture-form-password": True}
    form_password_key_errors = validate_summary(form_password_key_summary)
    assert any("form-password" in error for error in form_password_key_errors), form_password_key_errors
    assert "fixture-form-password" not in "\n".join(form_password_key_errors), form_password_key_errors
    redacted_form_password_summary = json.loads(json.dumps(summary, sort_keys=True))
    redacted_form_password_summary["evidence"] = {
        "formPassword": "<redacted>",
        "header": "X-Crypta-Form-Password: <redacted>",
    }
    assert not any("form-password" in error for error in validate_summary(redacted_form_password_summary)), (
        redacted_form_password_summary
    )
    structured_ci_token_summary = json.loads(json.dumps(summary, sort_keys=True))
    structured_ci_token_summary["evidence"] = {"GITHUB_TOKEN": "ghp_fixturetokenvalue"}
    assert any("ci-secret-value" in error for error in validate_summary(structured_ci_token_summary)), (
        structured_ci_token_summary
    )
    ci_token_key_summary = json.loads(json.dumps(summary, sort_keys=True))
    ci_token_key_summary["evidence"] = {"GITHUB_TOKEN=ghp_fixturetokenvalue": True}
    ci_token_key_errors = validate_summary(ci_token_key_summary)
    assert any("ci-secret-value" in error for error in ci_token_key_errors), ci_token_key_errors
    assert "ghp_fixturetokenvalue" not in "\n".join(ci_token_key_errors), ci_token_key_errors
    nested_ci_secret_summary = json.loads(json.dumps(summary, sort_keys=True))
    nested_ci_secret_summary["evidence"] = {"CRYPTAD_FOO_SECRET": {"value": "fixture-ci-secret"}}
    assert any("ci-secret-value" in error for error in validate_summary(nested_ci_secret_summary)), (
        nested_ci_secret_summary
    )
    redacted_ci_token_summary = json.loads(json.dumps(summary, sort_keys=True))
    redacted_ci_token_summary["evidence"] = {"GITHUB_TOKEN": "<redacted>"}
    assert not any("ci-secret-value" in error for error in validate_summary(redacted_ci_token_summary)), (
        redacted_ci_token_summary
    )
    structured_raw_app_data_summary = json.loads(json.dumps(summary, sort_keys=True))
    structured_raw_app_data_summary["evidence"] = {"rawAppData": "unredacted value"}
    assert any(
        "raw-app-data" in error for error in validate_summary(structured_raw_app_data_summary)
    ), structured_raw_app_data_summary
    nested_raw_app_data_summary = json.loads(json.dumps(summary, sort_keys=True))
    nested_raw_app_data_summary["evidence"] = {"rawAppData": {"value": "unredacted value"}}
    assert any(
        "raw-app-data" in error for error in validate_summary(nested_raw_app_data_summary)
    ), nested_raw_app_data_summary
    angle_bracketed_raw_summary = json.loads(json.dumps(summary, sort_keys=True))
    angle_bracketed_raw_summary["evidence"] = {
        "rawFetchedContent": "<html>secret</html>",
        "rawMessageBody": "<p>private social body</p>",
    }
    angle_bracketed_raw_errors = validate_summary(angle_bracketed_raw_summary)
    assert any("raw-fetched-content" in error for error in angle_bracketed_raw_errors), (
        angle_bracketed_raw_errors,
        angle_bracketed_raw_summary,
    )
    assert any("raw-social-message" in error for error in angle_bracketed_raw_errors), (
        angle_bracketed_raw_errors,
        angle_bracketed_raw_summary,
    )
    raw_payload_fields = {
        "raw-social-message": ("rawMessageBody", "private social message body"),
        "raw-trust-statement": ("rawTrustStatement", "signed trust statement body"),
        "raw-backup-payload": ("rawBackupPayload", "backup bundle bytes"),
        "raw-signature": ("rawSignature", "base64 signature bytes"),
    }
    for kind, (field_name, field_value) in raw_payload_fields.items():
        structured_payload_summary = json.loads(json.dumps(summary, sort_keys=True))
        structured_payload_summary["evidence"] = {field_name: field_value}
        assert any(kind in error for error in validate_summary(structured_payload_summary)), (
            kind,
            structured_payload_summary,
        )
        nested_payload_summary = json.loads(json.dumps(summary, sort_keys=True))
        nested_payload_summary["evidence"] = {field_name: {"value": field_value}}
        assert any(kind in error for error in validate_summary(nested_payload_summary)), (
            kind,
            nested_payload_summary,
        )
        redacted_payload_summary = json.loads(json.dumps(summary, sort_keys=True))
        redacted_payload_summary["evidence"] = {field_name: "<redacted>"}
        assert not any(kind in error for error in validate_summary(redacted_payload_summary)), (
            kind,
            redacted_payload_summary,
        )
    redaction_samples = {
        "private-insert-uri": "privateInsertUri=USK@AQECAAEPRIVATEINSERTKEY,fixture/name/1",
        "private-key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        "bearer-token": "Authorization: Bearer concrete-token-value",
        "session-token": "browserSessionToken=abcdef1234567890",
        "form-password-field": "formPassword=fixture-form-password",
        "form-password-header": "X-Crypta-Form-Password: fixture-form-password",
        "form-password-cli": "--form-password fixture-form-password",
        "github-token": "GITHUB_TOKEN=ghp_fixturetokenvalue",
        "cryptad-ci-secret": "CRYPTAD_FOO_SECRET=fixture-ci-secret",
        "raw-fetched-content": "rawFetchedContent: unredacted body",
        "raw-app-data": "rawAppData: unredacted value",
        "raw-social-message": "rawMessageBody: private social message body",
        "raw-trust-statement": "rawTrustStatement: signed trust statement body",
        "raw-backup-payload": "rawBackupPayload: backup bundle bytes",
        "raw-signature": "rawSignature: base64 signature bytes",
        "absolute-local-path": "/home/alice/.cryptad/private-state",
        "etc-absolute-local-path": "/etc/cryptad/private-state",
        "srv-absolute-local-path": "/srv/runner/work/cryptad/private-state",
        "file-uri-single-slash-local-path": "file:/home/alice/.cryptad/state",
        "file-uri-triple-slash-local-path": "file:///home/alice/.cryptad/state",
        "file-uri-localhost-local-path": "file://localhost/home/alice/.cryptad/state",
        "authorization-header": "Authorization: Basic abcdef123456",
        "authorization-assignment": "Authorization=Basic abcdef123456",
        "authorization-json-header": '"Authorization": "Digest abcdef123456"',
        "appledouble": "._secret-sidecar",
        "macosx": "__MACOSX/archive-sidecar",
    }
    for kind, text in redaction_samples.items():
        findings = scan_redaction_text(text, f"self-test.{kind}")
        assert findings, (kind, text)
    route_findings = scan_redaction_text(
        "GET /api/v1/content/fetch /apps/feed-reader/ /app/node/#diagnostics",
        "self-test.routes",
    )
    assert not any(finding["kind"] == "host-local-path" for finding in route_findings), route_findings
    leaky_compact_summary = json.loads(json.dumps(summary, sort_keys=True))
    leaky_compact_summary["blockers"] = ["rawBackupPayload: backup bundle bytes /srv/runner/work/cryptad/private"]
    leaky_compact_summary["warnings"] = ["/etc/cryptad/private-state"]
    leaky_compact_summary["redaction"] = {
        "status": "fail",
        "findings": [
            {
                "kind": "raw-backup-payload",
                "location": "/srv/runner/work/cryptad/private",
                "source": "validation",
                "rawBackupPayload": "backup bundle bytes",
            }
        ],
        "checks": dict.fromkeys(REDACTION_KEYS, True),
        "rawBackupPayload": "backup bundle bytes",
    }
    compact_json = stable_json(compact_for_release(leaky_compact_summary))
    for forbidden in ("rawBackupPayload", "backup bundle bytes", "/srv/runner", "/etc/cryptad"):
        assert forbidden not in compact_json, compact_json
    assert "raw-backup-payload" in compact_json, compact_json
    allowed = stable_json(build_summary(config, base_dir=fixture.parent)) + render_report(build_summary(config, base_dir=fixture.parent))
    assert "USK@AQECAAE" not in allowed
    assert "/home/" not in allowed
    assert "Authorization:" not in allowed
    print("multi-node beta soak self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline deterministic self-tests.")
    subparsers = parser.add_subparsers(dest="command")

    plan_parser = subparsers.add_parser("plan", help="Validate topology and write a deterministic drill plan.")
    plan_parser.add_argument("--config", type=Path, default=None)
    plan_parser.add_argument("--out", type=Path, default=None)
    plan_parser.add_argument("--mode", choices=MODES, default=None)
    plan_parser.add_argument("--strict", action="store_true")
    plan_parser.set_defaults(func=run_plan)

    run_parser = subparsers.add_parser("run", help="Run the simulated, hybrid, or live drill.")
    run_parser.add_argument("--config", type=Path, default=None)
    run_parser.add_argument("--out-dir", type=Path, required=True)
    run_parser.add_argument("--mode", choices=MODES, default=None)
    run_parser.add_argument("--require-live", action="store_true")
    run_parser.add_argument(
        "--require-all-scenarios",
        action="store_true",
        help="Fail disabled required drill scenarios without enabling full strict candidate-summary policy.",
    )
    run_parser.add_argument("--strict", action="store_true")
    run_parser.set_defaults(func=run_soak)

    verify_parser = subparsers.add_parser("verify", help="Validate a multi-node beta soak summary.")
    verify_parser.add_argument("--summary", type=Path, required=True)
    verify_parser.add_argument("--strict", action="store_true")
    verify_parser.set_defaults(func=run_verify)

    previous_parser = subparsers.add_parser(
        "previous-summary",
        help="Normalize release outputs into a previous beta candidate summary.",
    )
    previous_parser.add_argument("--release-certification-summary", type=Path, required=True)
    previous_parser.add_argument("--production-beta-summary", type=Path, required=True)
    previous_parser.add_argument("--out", type=Path, required=True)
    previous_parser.add_argument("--report", type=Path)
    previous_parser.add_argument("--generated-at")
    previous_parser.set_defaults(func=run_previous_summary)

    previous_verify_parser = subparsers.add_parser(
        "verify-previous-summary",
        help="Validate a previous beta candidate summary.",
    )
    previous_verify_parser.add_argument("--summary", type=Path, required=True)
    previous_verify_parser.add_argument("--report", type=Path)
    previous_verify_parser.add_argument("--strict", action="store_true")
    previous_verify_parser.add_argument("--max-age-days", type=int)
    previous_verify_parser.set_defaults(func=run_verify_previous_summary)

    previous_schema_parser = subparsers.add_parser(
        "previous-summary-schema",
        help="Write the JSON schema for previous beta candidate summaries.",
    )
    previous_schema_parser.add_argument("--out", type=Path)
    previous_schema_parser.set_defaults(func=run_previous_summary_schema)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

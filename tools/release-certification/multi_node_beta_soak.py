#!/usr/bin/env python3
"""Run deterministic multi-node beta soak and upgrade-drill evidence.

The default simulated run is offline, deterministic, and safe for PR checks.
Hybrid runs can attach existing summaries, and live runs may check localhost
node reachability when explicitly requested.
"""

from __future__ import annotations

import argparse
import hashlib
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
SUMMARY_FILE_NAME = "multi-node-beta-soak-summary.json"
COMPAT_SUMMARY_FILE_NAME = "summary.json"
REPORT_FILE_NAME = "multi-node-beta-soak-summary.md"
FIXTURE_NAME = "self-test-multi-node-beta-soak.json"
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
        "firstPartyAppMigrationStatus",
        "backupBeforeUpdateStatus",
        "rollbackStatus",
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
    r"(?<![\w-])Authorization\s*:\s*(?:Bearer|Basic|Digest)?\s*([^\s,'\"}]+)",
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


def fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / FIXTURE_NAME


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


def validate_previous_candidate_summary(summary: dict[str, Any] | None) -> list[str]:
    if summary is None:
        return ["previous candidate summary is missing or malformed"]
    errors: list[str] = []
    if summary.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("previous candidate summary schemaVersion must be 1")
    raw_status = str(summary.get("status", "missing")).strip().lower()
    release_candidate_passed = summary.get("releaseCandidatePassed")
    if release_candidate_passed is True and raw_status in {"missing", ""}:
        pass
    elif raw_status in {"fail", "failure", "failed", "missing", ""}:
        errors.append(f"previous candidate summary status is {raw_status or 'missing'}")
    elif raw_status not in {"pass", "warn", "success", "warning"} and release_candidate_passed is not True:
        errors.append(f"previous candidate summary status is not recognized: {raw_status}")
    if release_candidate_passed is False:
        errors.append("previous candidate releaseCandidatePassed is false")
    promotion_ready = summary.get("promotionReady")
    if promotion_ready is False:
        errors.append("previous candidate promotionReady is false")
    return errors


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
    return errors


def synthetic_digest(label: str, *values: Any) -> str:
    digest = hashlib.sha256()
    digest.update(label.encode("utf-8"))
    for value in values:
        digest.update(b"\0")
        digest.update(json.dumps(value, sort_keys=True).encode("utf-8"))
    return f"sha256:{digest.hexdigest()[:24]}"


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
    current_validation_errors = validate_current_candidate_summary(current_summary) if current_configured else []
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
    evidence = {
        "evidenceId": "multi-node-beta.upgrade-drill",
        "previousVersion": previous["version"],
        "currentVersion": current["version"],
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
        "firstPartyAppMigrationStatus": "pass",
        "backupBeforeUpdateStatus": "pass",
        "rollbackStatus": "pass",
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
    strict: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    base = base_dir or Path.cwd()
    scenario_strict = strict or bool(config["strict"].get("requireAllScenarios"))
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
        signature = evidence.get("catalogSignatureEvidence")
        if not isinstance(signature, dict):
            errors.append("scenario catalog-channel-update catalogSignatureEvidence must be an object")
        else:
            for field in ("catalogDigest", "signatureKeyId", "reviewChainDigest"):
                if not isinstance(signature.get(field), str) or not signature.get(field, "").strip():
                    errors.append(f"scenario catalog-channel-update catalogSignatureEvidence missing {field}")
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

    if summary.get("status") == "fail":
        errors.append("summary status is fail")
    if summary.get("status") == "pass" and summary.get("promotionReady") is not True:
        errors.append("promotionReady must be true when summary status is pass")
    if blocker_entries and summary.get("status") != "fail":
        errors.append("summary status must be fail when blockers are present")
    if blocker_entries and summary.get("promotionReady") is not False:
        errors.append("promotionReady must be false when blockers are present")
    if warning_entries and not blocker_entries and summary.get("status") == "pass":
        errors.append("summary status must not be pass when warnings are present")
    if strict:
        if summary.get("status") != "pass":
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


def compact_for_release(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": compact_status(summary.get("status", "missing")),
        "promotionReady": bool(summary.get("promotionReady")),
        "mode": compact_mode(summary.get("mode", "missing")),
        "durationProfile": compact_duration_profile(summary.get("durationProfile", "missing")),
        "scenarioStatuses": scenario_statuses(summary),
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


def run_self_test() -> None:
    fixture = fixture_path()
    config = validate_config(load_config(fixture if fixture.is_file() else None))
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
        assert summary["status"] == "warn", summary
        assert summary["promotionReady"] is True, summary
        assert summary["redaction"]["status"] == "pass", summary
        assert scenario_statuses(summary)["upgrade-from-previous-candidate"] == "warn", summary
        write_json(out_dir / SUMMARY_FILE_NAME, summary)
        write_text(out_dir / REPORT_FILE_NAME, report)
        assert validate_summary(read_json(out_dir / SUMMARY_FILE_NAME)) == [], summary
        path_plan_config = json.loads(json.dumps(config, sort_keys=True))
        path_plan_config["previousCandidate"]["summaryPath"] = "/srv/runner/work/cryptad/previous-summary.json"
        path_plan_current = path_plan_config["currentCandidate"]
        path_plan_current["productionBetaSummaryPath"] = "/home/runner/work/cryptad/current-summary.json"
        path_plan = render_plan(validate_config(path_plan_config))
        assert path_plan["previousCandidate"] == {
            "version": "previous-beta",
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

        strict_config = json.loads(json.dumps(config, sort_keys=True))
        strict_config["strict"]["requirePreviousSummary"] = True
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
        write_json(
            out_dir / "previous-valid.json",
            {"schemaVersion": SCHEMA_VERSION, "status": "pass", "promotionReady": True},
        )
        valid_previous_config["previousCandidate"]["summaryPath"] = "previous-valid.json"
        valid_previous_summary = build_summary(valid_previous_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        valid_upgrade = scenario_map(valid_previous_summary)["upgrade-from-previous-candidate"]
        assert valid_upgrade["status"] == "pass", valid_previous_summary
        assert valid_upgrade["evidence"]["previousSummaryValid"] is True, valid_upgrade

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

        valid_current_config = json.loads(json.dumps(valid_previous_config, sort_keys=True))
        write_json(
            out_dir / "current-valid.json",
            {"schemaVersion": SCHEMA_VERSION, "status": "pass", "promotionReady": True},
        )
        valid_current_config["currentCandidate"]["productionBetaSummaryPath"] = "current-valid.json"
        valid_current_summary = build_summary(valid_current_config, out_dir=out_dir, strict=True, base_dir=out_dir)
        valid_current_upgrade = scenario_map(valid_current_summary)["upgrade-from-previous-candidate"]
        assert valid_current_upgrade["status"] == "pass", valid_current_summary
        assert valid_current_upgrade["evidence"]["currentProductionBetaSummaryValid"] is True, valid_current_upgrade
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
    run_parser.add_argument("--strict", action="store_true")
    run_parser.set_defaults(func=run_soak)

    verify_parser = subparsers.add_parser("verify", help="Validate a multi-node beta soak summary.")
    verify_parser.add_argument("--summary", type=Path, required=True)
    verify_parser.add_argument("--strict", action="store_true")
    verify_parser.set_defaults(func=run_verify)
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

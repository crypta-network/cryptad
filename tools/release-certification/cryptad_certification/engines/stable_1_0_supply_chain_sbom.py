"""Deterministic SPDX 2.3 and reverse-index serialization for Stable releases."""

from __future__ import annotations

import re
from typing import Any

from .stable_1_0_supply_chain_core import (
    DIGEST_RE,
    REVERSE_INDEX_SCHEMA,
    SBOM_BINDING_SCHEMA,
    canonical_json_bytes,
    semantic_digest,
    sha256_digest,
    validate_document,
)

_SPDX_ID_RE = re.compile(r"[^A-Za-z0-9.-]")


def _spdx_id(prefix: str, identity: str) -> str:
    normalized = _SPDX_ID_RE.sub("-", identity).strip("-")
    return f"SPDXRef-{prefix}-{normalized[:180]}"


def _checksum(digest: str) -> dict[str, str]:
    if DIGEST_RE.fullmatch(digest) is None:
        raise ValueError("SPDX source digest is malformed")
    return {"algorithm": "SHA256", "checksumValue": digest.removeprefix("sha256:")}


def build_spdx(
    release: dict[str, Any],
    policy: dict[str, Any],
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
) -> dict[str, Any]:
    """Serialize the canonical component graph as deterministic SPDX 2.3 JSON."""

    inventory_digest = str(components_document["inventoryDigest"])
    namespace_suffix = sha256_digest(
        canonical_json_bytes(
            {
                "releaseId": release["releaseId"],
                "buildVersion": release["buildVersion"],
                "sourceCommit": release["sourceCommit"],
                "policyDigest": release["policyDigest"],
                "componentInventoryDigest": inventory_digest,
                "subjectInventoryDigest": subjects_document["subjectInventoryDigest"],
            }
        )
    ).removeprefix("sha256:")
    document_id = "SPDXRef-DOCUMENT"
    subject_packages: list[dict[str, Any]] = []
    component_packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    annotations: list[dict[str, str]] = []

    subject_spdx_ids: dict[str, str] = {}
    for subject in sorted(subjects_document["subjects"], key=lambda row: row["subjectKey"]):
        spdx_id = _spdx_id("Subject", subject["subjectKey"])
        subject_spdx_ids[subject["subjectKey"]] = spdx_id
        subject_packages.append(
            {
                "SPDXID": spdx_id,
                "name": subject["subjectKey"],
                "versionInfo": str(release["buildVersion"]),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [_checksum(subject["digest"])],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "APPLICATION",
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "crypta-release-subject",
                        "referenceLocator": subject["subjectKey"],
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": document_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            }
        )

    component_spdx_ids: dict[str, str] = {}
    for component in sorted(
        components_document["components"], key=lambda row: row["componentId"]
    ):
        component_id = component["componentId"]
        spdx_id = _spdx_id("Component", component_id)
        if spdx_id in component_spdx_ids.values():
            spdx_id = f"{spdx_id}-{sha256_digest(component_id.encode())[7:19]}"
        component_spdx_ids[component_id] = spdx_id
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": component["license"]["expression"],
            "licenseDeclared": component["license"]["expression"],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": _purpose(component["roles"]),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component_id,
                }
            ],
        }
        if component.get("digest") is not None:
            package["checksums"] = [_checksum(component["digest"])]
        component_packages.append(package)
        annotations.append(
            {
                "annotationType": "OTHER",
                "annotator": "Tool: cryptad-release-certification",
                "annotationDate": policy["effectiveAt"],
                "SPDXID": spdx_id,
                "comment": "Crypta roles: " + ",".join(component["roles"]),
            }
        )
        for subject_key in sorted(component["subjectKeys"]):
            relationships.append(
                {
                    "spdxElementId": subject_spdx_ids[subject_key],
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": spdx_id,
                }
            )
    for component in sorted(
        components_document["components"], key=lambda row: row["componentId"]
    ):
        source = component_spdx_ids[component["componentId"]]
        for dependency in sorted(component["relationships"]["dependsOn"]):
            target = component_spdx_ids.get(dependency)
            if target is None:
                raise ValueError("component graph references an absent dependency")
            relationships.append(
                {
                    "spdxElementId": source,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target,
                }
            )
    relationships.sort(
        key=lambda row: (
            row["spdxElementId"], row["relationshipType"], row["relatedSpdxElement"]
        )
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "name": f"Crypta Stable build {release['buildVersion']}",
        "documentNamespace": (
            "https://crypta.network/spdx/stable-1.0/"
            f"{release['releaseId']}/{namespace_suffix}"
        ),
        "creationInfo": {
            "created": policy["effectiveAt"],
            "creators": ["Tool: cryptad-release-certification"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": sorted(subject_spdx_ids.values()),
        "packages": subject_packages + component_packages,
        "relationships": relationships,
        "annotations": sorted(
            annotations, key=lambda row: (row["SPDXID"], row["comment"])
        ),
    }


def _purpose(roles: list[str]) -> str:
    if "runtime" in roles:
        return "LIBRARY"
    if "packaging" in roles or "publication" in roles:
        return "TOOL"
    if "build" in roles:
        return "BUILD_TOOL"
    return "TEST"


def build_sbom_binding(
    release: dict[str, Any],
    sbom: dict[str, Any],
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
) -> dict[str, Any]:
    """Bind exact SPDX bytes to the canonical graph and all exact subject bytes."""

    binding = {
        "schemaVersion": 1,
        "kind": "stable-1.0-sbom-binding",
        **release,
        "format": "SPDX-2.3-json",
        "documentNamespace": sbom["documentNamespace"],
        "sbomDigest": sha256_digest(
            __import__("json").dumps(
                sbom, ensure_ascii=False, indent=2, sort_keys=True
            ).encode("utf-8")
            + b"\n"
        ),
        "componentInventoryDigest": components_document["inventoryDigest"],
        "subjectInventoryDigest": subjects_document["subjectInventoryDigest"],
        "subjects": [
            {
                "subjectKey": row["subjectKey"],
                "subjectDigest": row["digest"],
            }
            for row in sorted(subjects_document["subjects"], key=lambda item: item["subjectKey"])
        ],
        "bindingDigest": "sha256:" + "0" * 64,
    }
    binding["bindingDigest"] = semantic_digest(binding, "bindingDigest")
    validate_document(binding, SBOM_BINDING_SCHEMA, "SBOM binding")
    return binding


def sbom_errors(
    supplied_sbom: dict[str, Any],
    binding: dict[str, Any],
    expected_sbom: dict[str, Any],
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
) -> list[str]:
    """Independently check SPDX bytes, namespace, graph, and subject partition bindings."""

    errors = validate_document_errors(binding, SBOM_BINDING_SCHEMA)
    if supplied_sbom != expected_sbom:
        errors.append("SPDX document diverges from the canonical component graph")
    expected_binding = build_sbom_binding(
        {
            key: binding[key]
            for key in (
                "releaseId",
                "buildVersion",
                "tag",
                "sourceCommit",
                "sourceRef",
                "policyDigest",
            )
        },
        supplied_sbom,
        components_document,
        subjects_document,
    )
    if binding != expected_binding:
        errors.append("SBOM binding does not authenticate the exact canonical SPDX bytes")
    return errors


def validate_document_errors(value: dict[str, Any], schema: str) -> list[str]:
    from cryptad_certification.schema_validation import validate_schema

    return validate_schema(value, schema)


def build_reverse_index(
    release: dict[str, Any],
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
) -> dict[str, Any]:
    """Build the public-safe component-to-build/package/app/catalog reverse index."""

    subjects = {
        row["subjectKey"]: row
        for row in subjects_document["subjects"]
    }
    entries = []
    for component in sorted(
        components_document["components"], key=lambda row: row["componentId"]
    ):
        subject_keys = sorted(component["subjectKeys"])
        apps = sorted(
            {
                app["appId"] + "@" + app["version"]
                for app in component["apps"]
            }
        )
        catalog_editions = sorted(
            {
                subjects[key]["catalogEdition"]
                for key in subject_keys
                if subjects[key].get("catalogEdition") is not None
            }
        )
        entries.append(
            {
                "componentId": component["componentId"],
                "version": component["version"],
                "digest": component.get("digest"),
                "runtimeComponentIds": sorted(component["runtimeComponentIds"]),
                "stableBuilds": [release["buildVersion"]],
                "subjectKeys": subject_keys,
                "apps": apps,
                "catalogEditions": catalog_editions,
            }
        )
    result = {
        "schemaVersion": 1,
        "kind": "stable-1.0-component-reverse-index",
        **release,
        "componentInventoryDigest": components_document["inventoryDigest"],
        "subjectInventoryDigest": subjects_document["subjectInventoryDigest"],
        "entries": entries,
        "reverseIndexDigest": "sha256:" + "0" * 64,
    }
    result["reverseIndexDigest"] = semantic_digest(result, "reverseIndexDigest")
    validate_document(result, REVERSE_INDEX_SCHEMA, "component reverse index")
    return result


def reverse_index_errors(
    supplied: dict[str, Any],
    release: dict[str, Any],
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
) -> list[str]:
    """Reject stale or self-reported reverse lookup data."""

    expected = build_reverse_index(release, components_document, subjects_document)
    errors = validate_document_errors(supplied, REVERSE_INDEX_SCHEMA)
    if supplied != expected:
        errors.append("component reverse index is stale or diverges from authenticated inventory")
    return errors

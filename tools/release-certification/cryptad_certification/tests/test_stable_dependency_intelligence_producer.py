"""Focused source-adapter tests for the protected dependency-intelligence producer."""

from __future__ import annotations

import unittest

from cryptad_certification.tests.test_stable_dependency_vulnerability_workflows import (
    osv_record,
    policy,
    producer,
)


class DependencyIntelligenceProducerAdapterTest(unittest.TestCase):
    def test_adaptRecords_whenOsvMavenPackageOmitsPurl_expectSelectorDerived(self) -> None:
        source = policy()["sources"][0]
        record = osv_record("OSV-2026-1")
        package = record["affected"][0]["package"]  # type: ignore[index]
        del package["purl"]  # type: ignore[index]

        result = producer.adapt_records(
            source, {"vulns": [record]}, policy()["networkBounds"]
        )

        claim = result[0]["packageClaims"][0]
        self.assertEqual("pkg:maven/com.example/demo", claim["purlSelector"])
        self.assertEqual("Maven", claim["ecosystem"])
        self.assertEqual("maven", claim["versionScheme"])

    def test_adaptRecords_whenOsvUnsupportedPackageOmitsPurl_expectBlockingSelectorDerived(
        self,
    ) -> None:
        source = policy()["sources"][0]
        record = osv_record("OSV-2026-1")
        record["affected"][0]["package"] = {  # type: ignore[index]
            "ecosystem": "npm",
            "name": "@babel/core",
        }

        result = producer.adapt_records(
            source, {"vulns": [record]}, policy()["networkBounds"]
        )

        claim = result[0]["packageClaims"][0]
        self.assertEqual("pkg:generic/npm/%40babel/core", claim["purlSelector"])
        self.assertEqual("Unknown", claim["ecosystem"])
        self.assertEqual("unsupported", claim["versionScheme"])
        self.assertEqual("unsupported-blocking", claim["ranges"][0]["rangeType"])

    def test_adaptRecords_whenOsvPackageSuppliesMalformedPurl_expectReject(self) -> None:
        source = policy()["sources"][0]
        record = osv_record("OSV-2026-1")
        record["affected"][0]["package"]["purl"] = None  # type: ignore[index]

        with self.assertRaisesRegex(
            producer.ProducerError,
            "dependency-intelligence-advisory-purl-invalid",
        ):
            producer.adapt_records(
                source, {"vulns": [record]}, policy()["networkBounds"]
            )

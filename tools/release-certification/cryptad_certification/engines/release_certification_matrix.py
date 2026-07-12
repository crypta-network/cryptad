"""Implementation segment for the matrix portion of ``release_certification.py``."""

from __future__ import annotations

def ecosystem_matrix_row_specs() -> list[MatrixRowSpec]:
    """Return the deterministic ecosystem certification row registry."""

    return [
        MatrixRowSpec(
            id="release-history-and-waivers",
            category="release-operations",
            title="Release history comparison and waiver visibility",
            gate_ids=("ecosystem.required-evidence-regressions",),
            optional_gate_ids=("ecosystem.waivers",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="history",
        ),
        MatrixRowSpec(
            id="ecosystem-certification-matrix",
            category="release-operations",
            title="Ecosystem certification matrix completeness",
            required_evidence_ids=("release-certification.ecosystem-matrix",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
        ),
        MatrixRowSpec(
            id=ECOSYSTEM_RC_MATRIX_ROW_ID,
            category="release-operations",
            title="Ecosystem RC certification gate",
            required_evidence_ids=(ECOSYSTEM_RC_EVIDENCE_ID,),
            gate_ids=(ECOSYSTEM_RC_GATE_ID,),
            docs=(
                "docs/release-certification.md",
                "docs/ecosystem-rc-certification-gate.md",
                "docs/cryptad-release-workflow-and-runbook.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="production-beta-go-no-go-dashboard",
            category="release-operations",
            title="Production beta go/no-go dashboard",
            required_evidence_ids=PRODUCTION_BETA_GO_NO_GO_EVIDENCE_IDS,
            docs=(
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/production-beta-release-pipeline.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="stable-1-0-readiness",
            category="release-operations",
            title="Stable 1.0 readiness gate",
            optional_evidence_ids=STABLE_1_0_READINESS_EVIDENCE_IDS,
            docs=(
                "docs/stable-1.0-readiness-gate.md",
                "docs/stable-1.0-known-limitations.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/release-certification.md",
            ),
            phase="phase-11",
            required_for_release_candidate=False,
            synthetic="stable-readiness",
        ),
        MatrixRowSpec(
            id="interop-smoke",
            category="network-compatibility",
            title="Hyphanet interop smoke certification",
            required_evidence_ids=("interop.smoke",),
            optional_evidence_ids=("interop.extended",),
            docs=("docs/release-certification.md", "tools/interop/README.md"),
        ),
        MatrixRowSpec(
            id="performance-smoke",
            category="performance",
            title="Performance regression smoke certification",
            required_evidence_ids=("performance.smoke",),
            docs=("docs/release-certification.md", "tools/perf/README.md"),
        ),
        MatrixRowSpec(
            id="live-network-beta-certification",
            category="network-compatibility",
            title="Live-network beta certification",
            optional_evidence_ids=LIVE_NETWORK_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.live-network-beta",),
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
                "docs/app-platform-beta-program.md",
                "docs/app-platform-beta-known-limitations.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="platform-api-contract",
            category="app-platform",
            title="Platform API contract compatibility",
            required_evidence_ids=(
                "platform-api.contract",
                *PLATFORM_API_STABLE_FREEZE_EVIDENCE_IDS,
            ),
            gate_ids=("ecosystem.platform-api-compatibility",),
            docs=(
                "docs/platform-api-contract.md",
                "docs/platform-api-1.0-stable-reference.md",
                "docs/platform-api-compatibility-support-window.md",
                "docs/platform-api-surface.md",
            ),
        ),
        MatrixRowSpec(
            id="developer-beta-toolkit",
            category="app-platform",
            title="Developer beta toolkit and CLI readiness",
            required_evidence_ids=(
                "app-platform.devtools-cli",
                "app-platform.developer-beta-toolkit",
            ),
            docs=("docs/app-dev-cli.md", "docs/developer-beta-toolkit.md"),
        ),
        MatrixRowSpec(
            id="app-platform-beta-docs-and-program",
            category="app-platform",
            title="App platform beta docs and program readiness",
            required_evidence_ids=(
                "app-platform.docs-portal",
                "app-platform.beta-program",
                "app-platform.beta-tutorials",
                "app-platform.docs-redaction",
            ),
            docs=(
                "docs/app-platform-developer-portal.md",
                "docs/app-platform-beta-tutorials.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/app-platform-beta-program.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="public-beta-docs-onboarding",
            category="app-platform",
            title="Public beta docs and onboarding readiness",
            required_evidence_ids=PUBLIC_BETA_ONBOARDING_EVIDENCE_IDS,
            docs=(
                "docs/public-beta/README.md",
                "docs/public-beta/user-guide.md",
                "docs/public-beta/install-update-rollback.md",
                "docs/public-beta/catalogs-and-apps.md",
                "docs/public-beta/permissions-and-consent.md",
                "docs/public-beta/trust-social-limitations.md",
                "docs/public-beta/developer-quickstart.md",
                "docs/public-beta/app-submission-walkthrough.md",
                "docs/public-beta/troubleshooting.md",
                "docs/public-beta/security-reporting.md",
                "docs/public-beta/legacy-plugin-authors.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="public-beta-support-feedback-loop",
            category="app-platform",
            title="Public beta support and feedback loop",
            required_evidence_ids=PUBLIC_BETA_SUPPORT_FEEDBACK_EVIDENCE_IDS,
            docs=(
                "docs/public-beta/support-and-feedback.md",
                "docs/public-beta/triage-taxonomy.md",
                "docs/public-beta/known-issues.md",
                "docs/public-beta/feedback-to-backlog.md",
                "docs/templates/beta-release-notes.md",
                "docs/privacy-preserving-beta-diagnostics.md",
                "docs/public-beta/security-reporting.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="app-vault-and-generated-documents",
            category="app-platform",
            title="App vault, identity profile publishing, and generated documents",
            required_evidence_ids=(
                "app-vault.capabilities",
                "app-platform.identity-profile-publish",
                "app-platform.generated-document-insert",
            ),
            gate_ids=("ecosystem.app-vault",),
            docs=(
                "docs/app-secret-and-identity-vault.md",
                "docs/platform-api-contract.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="content-fetch-and-networked-content",
            category="app-platform",
            title="Content fetch, subscriptions, and networked content surfaces",
            required_evidence_ids=(
                "app-platform.content-fetch",
                "app-platform.content-subscriptions",
                "network-content.subscription-scheduler",
                "app-platform.durable-app-data-store",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/platform-api-contract.md",
                "docs/feed-reader-reference-app.md",
                "docs/app-data-store.md",
            ),
        ),
        MatrixRowSpec(
            id="network-scale-soak-and-subscription-budget",
            category="app-platform",
            title="Network-scale soak and subscription budget",
            required_evidence_ids=(
                *NETWORK_SCALE_EVIDENCE_IDS,
                NETWORK_SCALE_SOAK_EVIDENCE_ID,
            ),
            docs=(
                "docs/network-scale-soak-and-subscription-budget.md",
                "docs/release-certification.md",
                "docs/social-inbox-reference-app.md",
                "docs/feed-reader-reference-app.md",
                "docs/trust-graph-preview.md",
            ),
            phase="phase-9",
            first_party_apps=("social-inbox", "feed-reader", "trust-graph"),
        ),
        MatrixRowSpec(
            id="multi-node-beta-soak-and-upgrade-drill",
            category="release-operations",
            title="Multi-node beta soak and upgrade drill",
            required_evidence_ids=MULTI_NODE_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.multi-node-beta",),
            docs=(
                "docs/multi-node-beta-soak-and-upgrade-drill.md",
                "docs/release-certification.md",
                "docs/production-beta-release-pipeline.md",
                "tools/release-certification/README.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
            ),
            phase="phase-10",
            first_party_apps=("feed-reader", "social-inbox", "trust-graph", "profile-publisher"),
        ),
        MatrixRowSpec(
            id="previous-candidate-upgrade-path",
            category="release-operations",
            title="Previous beta candidate upgrade path",
            required_evidence_ids=(
                "multi-node-beta.upgrade-drill",
                "multi-node-beta.app-install-update-rollback",
                "multi-node-beta.app-data-migration",
                "multi-node-beta.backup-restore",
                "multi-node-beta.social-inbox-multi-source",
                "multi-node-beta.trust-graph-import",
                "multi-node-beta.support-bundle-drill",
                "multi-node-beta.redaction",
            ),
            gate_ids=("ecosystem.multi-node-beta",),
            docs=(
                "docs/multi-node-beta-soak-and-upgrade-drill.md",
                "docs/production-beta-release-pipeline.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/app-data-backup-restore-portability.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
            first_party_apps=("feed-reader", "social-inbox", "trust-graph", "profile-publisher"),
        ),
        MatrixRowSpec(
            id="app-data-backup-restore-portability",
            category="app-platform",
            title="App-data backup, restore, and portability",
            required_evidence_ids=(
                "app-platform.durable-app-data-store",
                "app-data.backup-restore-portability",
                "operator-beta.app-data-backup-restore",
            ),
            docs=(
                "docs/app-data-backup-restore-portability.md",
                "docs/app-data-store.md",
                "docs/operator-beta-dashboard.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="trust-graph-preview-platform",
            category="app-platform",
            title="Trust Graph Local RC platform routes and signing",
            required_evidence_ids=(
                "app-platform.trust-graph-preview",
                "app-platform.trust-graph-rc-scope-and-safety",
                "app-platform.trust-graph-durable-store",
                "app-platform.trust-graph-exchange",
                "app-platform.trust-social-beta-hardening",
                "app-platform.trust-statement-signing",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md", "docs/platform-api-contract.md"),
        ),
        MatrixRowSpec(
            id="app-service-discovery-and-grants",
            category="app-platform",
            title="App-service discovery, grants, dependency graph, and grant bundles",
            required_evidence_ids=APP_SERVICE_DISCOVERY_AND_GRANT_EVIDENCE_IDS,
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/app-service-discovery-and-grants.md",
                "docs/platform-api-contract.md",
                "docs/social-inbox-reference-app.md",
                "docs/trust-graph-preview.md",
            ),
        ),
        MatrixRowSpec(
            id="apphost-sandbox-provider",
            category="app-platform",
            title="AppHost sandbox-provider enforcement",
            required_evidence_ids=("apphost.sandbox-provider",),
            optional_evidence_ids=("apphost.live",),
            gate_ids=("ecosystem.sandbox-provider",),
            docs=("docs/apphost-runtime-hardening.md", "docs/release-certification.md"),
        ),
        MatrixRowSpec(
            id="public-beta-security-hardening",
            category="security-redaction",
            title="Public beta security hardening",
            required_evidence_ids=PUBLIC_BETA_SECURITY_EVIDENCE_IDS,
            gate_ids=(
                "ecosystem.app-ui-quality",
                "ecosystem.reference-content-apps",
                "ecosystem.sandbox-provider",
                "ecosystem.app-review-trust",
            ),
            docs=(
                "docs/SECURITY.md",
                "docs/app-owned-ui.md",
                "docs/feed-reader-reference-app.md",
                "docs/social-inbox-reference-app.md",
                "docs/trust-graph-preview.md",
                "docs/apphost-runtime-hardening.md",
                "docs/release-certification.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="app-platform-user-consent-flow",
            category="app-platform",
            title="User consent and permission-upgrade flow",
            required_evidence_ids=("app-platform.user-consent-flow",),
            docs=(
                "docs/user-consent-and-permission-upgrade-ux.md",
                "docs/app-update-lifecycle.md",
                "docs/app-catalogs.md",
                "docs/app-service-discovery-and-grants.md",
                "docs/app-data-store.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
        ),
        MatrixRowSpec(
            id="app-update",
            category="app-platform",
            title="App update lifecycle, scheduler, and rollback",
            required_evidence_ids=(
                "app-update.lifecycle",
                "app-update.scheduler",
                "app-update.live-catalog-refresh",
                "app-update.rollback",
                "app-update.data-migration-contract",
            ),
            gate_ids=("ecosystem.app-update-rollback",),
            docs=(
                "docs/app-update-lifecycle.md",
                "docs/app-upgrade-data-migrations.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="privacy-preserving-diagnostics-risk",
            category="security-redaction",
            title="Privacy-preserving beta diagnostics",
            required_evidence_ids=(
                "app-platform.privacy-preserving-beta-diagnostics",
                "operator-beta.support-bundle-redaction",
                "operator-rc.support-bundle-wizard",
                "multi-node-beta.support-bundle-drill",
            ),
            gate_ids=("ecosystem.operator-rc-recovery", "ecosystem.multi-node-beta"),
            docs=(
                "docs/privacy-preserving-beta-diagnostics.md",
                "docs/operator-beta-dashboard.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/production-beta-go-no-go-dashboard.md",
                "docs/production-beta-release-pipeline.md",
                "docs/production-security-response-runbook.md",
                "docs/SECURITY.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="operator-beta-ux-and-recovery",
            category="app-platform",
            title="Operator beta dashboard, recovery, and support bundle",
            required_evidence_ids=OPERATOR_BETA_EVIDENCE_IDS,
            docs=(
                "docs/operator-beta-dashboard.md",
                "docs/platform-api-surface.md",
                "docs/app-platform-beta-program.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/release-certification.md",
            ),
            phase="phase-8",
        ),
        MatrixRowSpec(
            id="operator-rc-recovery-and-support-workflow",
            category="app-platform",
            title="Operator RC recovery and support workflow",
            required_evidence_ids=OPERATOR_RC_EVIDENCE_IDS,
            gate_ids=("ecosystem.operator-rc-recovery",),
            docs=(
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/operator-beta-dashboard.md",
                "docs/platform-api-surface.md",
                "docs/app-platform-beta-known-limitations.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="first-party-beta-catalog",
            category="app-distribution",
            title="First-party beta catalog and signed bundles",
            required_evidence_ids=(
                "catalog.smoke",
                "catalog.live-usk-publication",
                "catalog.live-usk-source-verification",
                "app-catalog.first-party-beta",
                "app-platform.signed-bundles",
            ),
            docs=("docs/first-party-beta-catalog.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="production-catalog-channels",
            category="app-distribution",
            title="Production first-party catalog channels",
            required_evidence_ids=("catalog.production-channels",),
            docs=(
                "docs/production-first-party-catalog-channels.md",
                "docs/app-catalogs.md",
                "docs/app-update-lifecycle.md",
                "docs/platform-api-surface.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="catalog-operations-and-mirrors",
            category="app-distribution",
            title="Catalog operations and mirrors",
            required_evidence_ids=("catalog.operations-and-mirrors",),
            docs=(
                "docs/catalog-operations-and-mirrors.md",
                "docs/app-catalogs.md",
                "docs/production-security-response-runbook.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="first-party-app-maintenance-policy",
            category="app-distribution",
            title="First-party app maintenance policy",
            required_evidence_ids=("app-catalog.first-party-maintenance-policy",),
            docs=(
                "docs/first-party-app-maintenance-policy.md",
                "docs/app-catalogs.md",
                "docs/production-first-party-catalog-channels.md",
                "docs/production-beta-release-pipeline.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
            first_party_apps=(
                "queue-manager",
                "publisher",
                "site-publisher",
                "profile-publisher",
                "feed-reader",
                "social-inbox",
                "trust-graph",
            ),
        ),
        MatrixRowSpec(
            id="ecosystem-security-advisory-and-revocation",
            category="security-redaction",
            title="Ecosystem security advisory and revocation response",
            required_evidence_ids=ECOSYSTEM_SECURITY_EVIDENCE_IDS,
            gate_ids=("ecosystem.security-advisory-revocation",),
            docs=(
                "docs/ecosystem-security-advisories.md",
                "docs/app-catalogs.md",
                "docs/production-first-party-catalog-channels.md",
                "docs/app-review-governance.md",
                "docs/app-update-lifecycle.md",
                "docs/SECURITY.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="production-security-response-runbook",
            category="security-redaction",
            title="Production security response runbook",
            required_evidence_ids=PRODUCTION_SECURITY_EVIDENCE_IDS,
            gate_ids=("ecosystem.security-advisory-revocation", "ecosystem.operator-rc-recovery"),
            docs=(
                "docs/production-security-response-runbook.md",
                "docs/templates/security-release-notes.md",
                "docs/SECURITY.md",
                "docs/ecosystem-security-advisories.md",
                "docs/app-catalogs.md",
                "docs/app-review-governance.md",
                "docs/operator-rc-recovery-and-support-workflow.md",
                "docs/production-beta-release-pipeline.md",
                "docs/release-certification.md",
                "tools/release-certification/README.md",
            ),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="review-trusted-receipts",
            category="review-governance",
            title="Trusted app-review receipts and policy",
            required_evidence_ids=(
                "app-review.trusted-receipts",
                "app-review.policy",
                "app-review.first-party-catalog",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md", "docs/app-catalogs.md"),
        ),
        MatrixRowSpec(
            id="review-governance-transparency",
            category="review-governance",
            title="Review governance, transparency log, and review history",
            required_evidence_ids=(
                "app-review.governance",
                "app-review.reviewer-key-lifecycle",
                "app-review.transparency-log",
                "app-review.review-history-api",
                "app-review.first-party-review-chain",
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=("docs/app-review-governance.md",),
        ),
        MatrixRowSpec(
            id="app-store-submission-and-review",
            category="review-governance",
            title="Third-party app submission and review workflow",
            required_evidence_ids=(
                *APP_STORE_SUBMISSION_EVIDENCE_IDS,
                *THIRD_PARTY_INTAKE_EVIDENCE_IDS,
            ),
            gate_ids=("ecosystem.app-review-trust",),
            docs=(
                "docs/app-store-submission-and-review-workflow.md",
                "docs/app-dev-cli.md",
                "docs/app-review-governance.md",
                "docs/app-catalogs.md",
                "docs/production-beta-release-pipeline.md",
            ),
        ),
        MatrixRowSpec(
            id="third-party-developer-beta-program",
            category="review-governance",
            title="Third-party developer beta program",
            required_evidence_ids=THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS,
            gate_ids=("ecosystem.app-review-trust",),
            docs=(
                "docs/third-party-developer-beta-program.md",
                "docs/third-party-app-submission-checklist.md",
                "docs/platform-api-compatibility-support-window.md",
                "docs/examples/third-party-hello-stable.md",
                "docs/app-store-submission-and-review-workflow.md",
                "docs/app-catalogs.md",
                "docs/legacy-plugin-migration-guide.md",
                "docs/release-certification.md",
            ),
        ),
        MatrixRowSpec(
            id="ui-design-system",
            category="first-party-apps",
            title="App UI design-system adoption and lint",
            required_evidence_ids=(
                "app-ui.design-system",
                "app-ui.lint",
                "app-ui.first-party-adoption",
                "app-ui.smoke",
            ),
            gate_ids=("ecosystem.app-ui-quality",),
            docs=("docs/app-ui-design-system.md", "docs/app-owned-ui.md"),
        ),
        MatrixRowSpec(
            id="first-party-app-bundles",
            category="first-party-apps",
            title="First-party app bundle set and beta quality",
            required_evidence_ids=(
                "app-platform.first-party",
                FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
            ),
            gate_ids=("ecosystem.first-party-apps",),
            docs=(
                "docs/first-party-beta-catalog.md",
                "docs/first-party-app-beta-quality-pass.md",
                "docs/app-distribution.md",
            ),
            first_party_apps=EXPECTED_FIRST_PARTY_APPS,
        ),
        MatrixRowSpec(
            id="reference-content-apps",
            category="reference-apps",
            title="Site Publisher reference content app",
            required_evidence_ids=("reference-apps.content",),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md", "docs/app-distribution.md"),
            first_party_apps=("site-publisher",),
        ),
        MatrixRowSpec(
            id="profile-publisher",
            category="reference-apps",
            title="Profile Publisher reference app",
            required_evidence_ids=(
                "reference-app.profile-publisher",
                "reference-app.profile-publisher-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/first-party-beta-catalog.md",),
            first_party_apps=("profile-publisher",),
        ),
        MatrixRowSpec(
            id="feed-reader",
            category="reference-apps",
            title="Feed Reader reference app",
            required_evidence_ids=(
                "reference-app.feed-reader",
                "reference-app.feed-reader-subscriptions",
                "reference-app.feed-reader-app-data",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/feed-reader-reference-app.md",),
            first_party_apps=("feed-reader",),
        ),
        MatrixRowSpec(
            id="trust-graph-app",
            category="reference-apps",
            title="Trust Graph Local RC reference app",
            required_evidence_ids=(
                "reference-app.trust-graph",
                "reference-app.trust-graph-durable-exchange",
                "reference-app.trust-graph-app-data-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=("docs/trust-graph-preview.md",),
            first_party_apps=("trust-graph",),
        ),
        MatrixRowSpec(
            id="social-inbox-preview",
            category="reference-apps",
            title="Social Inbox RC message-threading reference app",
            required_evidence_ids=(
                "app-platform.social-message-signing",
                "reference-app.social-inbox",
                "reference-app.social-inbox-signed-message",
                "reference-app.social-inbox-subscriptions",
                "reference-app.social-inbox-app-data",
                "reference-app.social-inbox-trust-annotations",
                "reference-app.social-inbox-rc-threading",
                "app-platform.trust-social-beta-hardening",
                "app-platform.trust-social-content-format-profiles",
                "reference-app.social-inbox-service-grant",
                "reference-app.social-inbox-service-dependency",
                "migration.social-mail-preview",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/social-inbox-reference-app.md",
                "docs/platform-api-contract.md",
                "docs/app-secret-and-identity-vault.md",
                "docs/app-service-discovery-and-grants.md",
            ),
            first_party_apps=("social-inbox",),
        ),
        MatrixRowSpec(
            id="legacy-plugin-migration",
            category="legacy-retirement",
            title="Legacy plugin-to-app migration guidance",
            required_evidence_ids=(
                "legacy-plugin.freeze-policy",
                "legacy-plugin.migration-guide",
                "legacy-plugin.social-inbox-spike",
                "legacy-plugin.migration-finalization",
            ),
            gate_ids=("ecosystem.reference-content-apps",),
            docs=(
                "docs/legacy-plugin-freeze-policy.md",
                "docs/legacy-plugin-migration-guide.md",
                "docs/legacy-plugin-migration-cookbook.md",
                "docs/templates/plugin-migration-plan.md",
                "docs/plugin-system.md",
                "docs/social-inbox-reference-app.md",
                "docs/app-service-discovery-and-grants.md",
            ),
            first_party_apps=("social-inbox", "trust-graph"),
            phase="phase-9",
        ),
        MatrixRowSpec(
            id="legacy-retirement",
            category="legacy-retirement",
            title="Legacy admin retirement and removal waves",
            required_evidence_ids=(
                "legacy.retirement",
                "legacy-admin.removal-wave-1",
                "legacy-admin.removal-wave-2",
                "legacy-admin.removal-wave-3",
                "legacy-admin.removal-wave-4",
                "legacy-admin.removal-wave-5",
                "legacy-admin.final-admin-surface",
                "legacy-admin.browse-retained",
                "legacy-admin.emergency-fallback-retained",
            ),
            gate_ids=("ecosystem.legacy-retirement",),
            docs=("docs/legacy-retirement-plan.md", "docs/release-certification.md"),
            phase="phase-10",
        ),
        MatrixRowSpec(
            id="redaction-and-private-artifacts",
            category="security-redaction",
            title="Redaction and private artifact exclusions",
            docs=(
                "docs/release-certification.md",
                "tools/release-certification/README.md",
                "docs/cryptad-release-workflow-and-runbook.md",
            ),
            synthetic="redaction",
        ),
    ]

def required_stable_readiness_blocking(settings: Settings, rows: Any) -> bool:
    if not settings.stable_readiness_required:
        return False
    if not isinstance(rows, list):
        return True
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("id") == STABLE_1_0_READINESS_MATRIX_ROW_ID:
            return bool(row.get("releaseBlocker"))
    return True

def matrix_status_from_counts(mode: str, counts: dict[str, int], coverage: dict[str, Any]) -> str:
    release_blockers = counts.get("releaseBlockers", 0)
    warnish_rows = sum(counts.get(status, 0) for status in ("warn", "missing", "skip"))
    redaction_failed = coverage.get("redactionPassed") is False
    unwaived_coverage_issue_ids = [
        str(issue_id) for issue_id in coverage.get("unwaivedIssueIds", coverage.get("issueIds", [])) if issue_id
    ]
    coverage_warn = bool(coverage.get("issueIds")) or not all(
        bool(coverage.get(key))
        for key in ("requiredEvidenceCovered", "ecosystemGatesCovered", "firstPartyAppsCovered", "docsCovered")
    )
    if mode == "pr":
        if redaction_failed:
            return "fail"
        return "warn" if release_blockers or warnish_rows or coverage_warn else "pass"
    if mode == "release-candidate" and (release_blockers or redaction_failed or unwaived_coverage_issue_ids):
        return "fail"
    if redaction_failed:
        return "fail"
    if release_blockers or warnish_rows or coverage_warn:
        return "warn"
    return "pass"

def previous_matrix_row_statuses(previous_summary: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(previous_summary, dict):
        return {}
    compact = previous_summary.get("ecosystemMatrix")
    if not isinstance(compact, dict):
        return {}
    statuses = compact.get("rowStatuses")
    if isinstance(statuses, dict):
        return {
            str(row_id): normalize_evidence_status(str(status))
            for row_id, status in statuses.items()
        }
    rows = compact.get("rows")
    if isinstance(rows, list):
        return {
            str(row.get("id")): normalize_evidence_status(str(row.get("status", "missing")))
            for row in rows
            if isinstance(row, dict) and row.get("id")
        }
    return {}

def regression_status_for_row(
    spec: MatrixRowSpec,
    status: str,
    release_blocker: bool,
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
) -> tuple[str, str]:
    if not previous_summary_present:
        return "missing", "not-comparable"
    if not previous_matrix_present:
        return "missing", "previous-missing"
    previous_status = previous_row_statuses.get(spec.id)
    if previous_status is None:
        return "missing", "new-row"
    previous_severity = status_severity(previous_status)
    current_severity = status_severity(status)
    if current_severity > previous_severity:
        return previous_status, "regressed-blocker" if release_blocker or status == "fail" else "regressed-warning"
    if current_severity < previous_severity:
        return previous_status, "improved"
    return previous_status, "unchanged"

def gate_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return "missing"
    return normalize_evidence_status(str(entry.get("status", "missing")))

def aggregate_status_values(values: list[str], *, missing_if_empty: bool = False) -> str:
    normalized = [normalize_evidence_status(value) for value in values]
    if not normalized:
        return "missing" if missing_if_empty else "pass"
    if any(value == "fail" for value in normalized):
        return "fail"
    if any(value == "warn" for value in normalized):
        return "warn"
    if any(value == "missing" for value in normalized):
        return "missing"
    if any(value == "skip" for value in normalized):
        return "skip"
    return "pass"

def unwaivable_matrix_issue_ids(
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> set[str]:
    unwaivable_issue_ids = set(unwaivable_evidence_ids)
    unwaivable_issue_ids.update(
        f"evidence.{evidence_id}" for evidence_id in unwaivable_evidence_ids
    )
    if extra_unwaivable_issue_ids:
        unwaivable_issue_ids.update(extra_unwaivable_issue_ids)
    return unwaivable_issue_ids

def waivable_matrix_issue_ids(
    issue_ids: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> list[str]:
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    return [issue_id for issue_id in issue_ids if issue_id not in unwaivable_issue_ids]

def row_waivers(
    spec: MatrixRowSpec,
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> tuple[list[WaiverRecord], list[str]]:
    records: dict[str, WaiverRecord] = {}
    unwaivable_issue_ids = unwaivable_matrix_issue_ids(
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    waivable_issue_ids = waivable_matrix_issue_ids(
        issue_ids,
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    targets = [spec.id, *spec.evidence_ids(), *spec.all_gate_ids()]
    if unwaivable_evidence_ids or extra_unwaivable_issue_ids:
        targets = [
            target_id
            for target_id in targets
            if target_id != spec.id and target_id not in unwaivable_evidence_ids
        ]
    for target_id in targets:
        waiver = active_waiver_for(context, target_id, waivable_issue_ids, mode)
        if waiver is not None:
            records[waiver.id] = waiver
    for evidence_id in spec.evidence_ids():
        if evidence_id in unwaivable_evidence_ids:
            continue
        for waiver_id in detail_waiver_ids(evidence_details(evidence_entries.get(evidence_id))):
            waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
            if waiver is not None:
                records[waiver.id] = waiver
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        details = gate.get("details", {}) if isinstance(gate, dict) else {}
        if isinstance(details, dict):
            for waiver_id in detail_waiver_ids(details):
                if str(waiver_id) in unwaivable_issue_ids:
                    continue
                waiver = active_waiver_for(context, str(waiver_id), waivable_issue_ids, mode)
                if waiver is not None:
                    records[waiver.id] = waiver
    waiver_ids = sorted(records)
    return [records[waiver_id] for waiver_id in waiver_ids], waiver_ids

def row_release_blocker_waiver(
    spec: MatrixRowSpec,
    context: WaiverContext,
    mode: str,
    issue_ids: list[str],
    blocker_targets: list[str],
    unwaivable_evidence_ids: set[str],
    extra_unwaivable_issue_ids: set[str] | None = None,
) -> WaiverRecord | None:
    if unwaivable_evidence_ids.intersection(blocker_targets):
        return None
    if extra_unwaivable_issue_ids and extra_unwaivable_issue_ids.intersection(issue_ids):
        return None
    waivable_issue_ids = waivable_matrix_issue_ids(
        issue_ids,
        unwaivable_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    return active_waiver_for(
        context,
        spec.id,
        sorted(dict.fromkeys(waivable_issue_ids + blocker_targets)),
        mode,
    )

def row_recommendation(
    status: str,
    release_blocker: bool,
    waiver_ids: list[str],
    missing_required: list[str],
    gate_blockers: list[str],
    previous_matrix_missing_warning: bool,
) -> str:
    if status == "pass":
        return "No release action required."
    if previous_matrix_missing_warning:
        return "Record the previous-summary matrix gap in the release log."
    if waiver_ids:
        return "Review waived evidence before release-candidate promotion."
    if release_blocker and missing_required:
        return "Restore missing required evidence before release-candidate promotion."
    if release_blocker and gate_blockers:
        return "Resolve release-blocking ecosystem gate or record an approved waiver."
    if release_blocker:
        return "Review failing evidence and rerun release certification."
    if status == "missing":
        return "Restore missing required evidence before release-candidate promotion."
    if status == "skip":
        return "Review skipped evidence before release-candidate promotion."
    return "Review warning evidence or record an approved waiver."

def safe_waiver_summaries(records: list[WaiverRecord]) -> dict[str, str]:
    return {record.id: record.reason for record in records}

def evaluate_matrix_row(
    spec: MatrixRowSpec,
    settings: Settings,
    evidence_entries: dict[str, dict[str, Any]],
    previous_evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    history_comparison: dict[str, Any],
    previous_summary_present: bool,
    previous_matrix_present: bool,
    previous_row_statuses: dict[str, str],
    waiver_context: WaiverContext,
    redaction: dict[str, bool],
) -> dict[str, Any]:
    required_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.required_evidence_ids
    }
    optional_statuses = {
        evidence_id: evidence_status(evidence_entries.get(evidence_id))
        for evidence_id in spec.optional_evidence_ids
    }
    unwaivable_redaction_evidence_ids = {
        evidence_id
        for evidence_id in spec.evidence_ids()
        if evidence_entry_has_unwaivable_redaction_findings(evidence_entries.get(evidence_id))
    }
    previous_statuses = {
        evidence_id: evidence_status(previous_evidence_entries.get(evidence_id))
        for evidence_id in spec.evidence_ids()
    }
    gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.gate_ids
    }
    optional_gate_statuses = {
        gate_id: gate_status(gate_entries.get(gate_id))
        for gate_id in spec.optional_gate_ids
        if gate_id in gate_entries
    }
    stable_not_requested = False
    issue_ids: list[str] = []
    extra_unwaivable_issue_ids: set[str] = set()
    gate_blockers: list[str] = []
    gate_warnings: list[str] = []
    for gate_id in spec.all_gate_ids():
        gate = gate_entries.get(gate_id)
        if not isinstance(gate, dict):
            if gate_id in spec.gate_ids:
                issue_ids.append(f"matrix.gate-missing.{gate_id}")
            continue
        details = gate.get("details", {})
        if isinstance(details, dict):
            issue_ids.extend(str(value) for value in details.get("issueIds", []) if value)
        status = gate_status(gate)
        if status == "fail" and gate.get("releaseBlocker"):
            gate_blockers.append(gate_id)
        elif status in {"warn", "fail", "missing"}:
            gate_warnings.append(gate_id)

    missing_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "missing"
    ]
    skipped_required = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "skip"
    ]
    skipped_required_non_rc = skipped_required if settings.mode != "release-candidate" else []
    required_skip_only = (
        bool(spec.required_evidence_ids)
        and settings.mode != "release-candidate"
        and all(status == "skip" for status in required_statuses.values())
    )
    required_bad = [
        evidence_id
        for evidence_id, status in required_statuses.items()
        if status in {"fail", "missing"} or (status == "skip" and settings.mode == "release-candidate")
    ]
    required_warn = [
        evidence_id for evidence_id, status in required_statuses.items() if status == "warn"
    ]
    optional_warn: list[str] = []
    for evidence_id, status in optional_statuses.items():
        if (
            evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS
            and status == "missing"
            and not settings.stable_readiness_required
        ):
            continue
        if status in {"fail", "warn", "missing"}:
            optional_warn.append(evidence_id)
        elif status == "skip":
            evidence_details_value = evidence_details(evidence_entries.get(evidence_id))
            live_beta_disabled_skip = (
                evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS
                and not settings.live_network_beta_enabled
                and not settings.live_network_beta_required
                and not bool(evidence_details_value.get("enabled"))
            )
            if live_beta_disabled_skip:
                continue
            if evidence_id == "apphost.live":
                continue
            if evidence_id == "live-network-beta.app-service-score" and not bool(
                evidence_details_value.get("enabled")
            ):
                continue
            optional_warn.append(evidence_id)
    if required_bad:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_bad)
    if required_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in required_warn)
    if skipped_required_non_rc:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in skipped_required_non_rc)
    if optional_warn:
        issue_ids.extend(f"evidence.{evidence_id}" for evidence_id in optional_warn)
    blocker_targets = sorted(dict.fromkeys(required_bad + gate_blockers))

    previous_matrix_missing_warning = (
        spec.synthetic == "history"
        and previous_summary_present
        and not previous_matrix_present
        and settings.mode in {"nightly", "release-candidate"}
    )
    history_status = normalize_evidence_status(str(history_comparison.get("status", "missing")))
    if spec.synthetic == "history":
        if history_status == "fail" or gate_blockers:
            status = "fail"
            release_blocker = True
        elif history_status in {"warn", "missing"} or gate_warnings or previous_matrix_missing_warning:
            status = "warn"
            release_blocker = False
        else:
            status = "pass"
            release_blocker = False
        if waiver_context.records:
            status = "warn" if status == "pass" else status
        if waiver_context.errors and settings.mode == "release-candidate":
            status = "fail"
            release_blocker = True
        summary = "History comparison and waiver validation are visible in the release record."
    elif spec.synthetic == "redaction":
        release_blocker = not all(redaction.values())
        status = "fail" if release_blocker else "pass"
        summary = "Certification summaries and copied artifacts exclude private material."
        if release_blocker:
            issue_ids.append("matrix.redaction.failed")
    elif spec.synthetic == "stable-readiness":
        attached = any(evidence_id in evidence_entries for evidence_id in spec.evidence_ids())
        main_entry = evidence_entries.get("stable-1.0.readiness-gate")
        redaction_entry = evidence_entries.get("stable-1.0.redaction")
        main_status = evidence_status(main_entry)
        redaction_status = evidence_status(redaction_entry)
        main_details = evidence_details(main_entry)
        decision = str(main_details.get("decision", "not-attached"))
        stable_ready = main_details.get("stableReady") is True
        redaction_failed = (
            redaction_status != "pass"
            or bool(unwaivable_redaction_evidence_ids)
            or evidence_entry_has_unwaivable_redaction_findings(main_entry)
            or evidence_entry_has_unwaivable_redaction_findings(redaction_entry)
        )
        stable_evidence_bad = [
            evidence_id
            for evidence_id in spec.evidence_ids()
            if evidence_status(evidence_entries.get(evidence_id)) in {"fail", "missing", "skip"}
        ]
        stable_evidence_warn = [
            evidence_id
            for evidence_id in spec.evidence_ids()
            if evidence_status(evidence_entries.get(evidence_id)) == "warn"
        ]
        if not attached and not settings.stable_readiness_required:
            status = "pass"
            release_blocker = False
            stable_not_requested = True
            summary = "Stable 1.0 readiness was not requested for this certification run."
            issue_ids = [
                issue_id
                for issue_id in issue_ids
                if not issue_id.startswith("evidence.stable-1.0.")
            ]
        elif not attached:
            status = "fail"
            release_blocker = True
            summary = "Stable 1.0 readiness is required but no summary was attached."
            issue_ids.append("matrix.stable-readiness.required-missing")
            extra_unwaivable_issue_ids.add("matrix.stable-readiness.required-missing")
        elif redaction_failed:
            status = "fail"
            release_blocker = True
            summary = "Stable 1.0 readiness redaction findings are non-waivable."
            if redaction_status == "fail" or not unwaivable_redaction_evidence_ids:
                unwaivable_redaction_evidence_ids.add("stable-1.0.redaction")
            extra_unwaivable_issue_ids.add("matrix.stable-readiness.redaction-failed")
            blocker_targets.extend(sorted(unwaivable_redaction_evidence_ids))
            issue_ids.append("matrix.stable-readiness.redaction-failed")
        elif stable_evidence_bad:
            release_blocker = settings.stable_readiness_required
            status = "fail" if release_blocker else "warn"
            summary = (
                "Stable 1.0 readiness is required but expected evidence is missing or failing."
                if release_blocker
                else "Stable 1.0 readiness advisory evidence is missing or failing."
            )
            issue_ids.append("matrix.stable-readiness.evidence-not-passing")
            if release_blocker:
                extra_unwaivable_issue_ids.add(
                    "matrix.stable-readiness.evidence-not-passing"
                )
                blocker_targets.extend(stable_evidence_bad)
        elif main_status == "fail" or not stable_ready or decision == "not-ready":
            release_blocker = settings.stable_readiness_required
            status = "fail" if release_blocker else "warn"
            summary = (
                "Stable 1.0 readiness is required and not passing."
                if release_blocker
                else "Stable 1.0 readiness is attached as advisory evidence and is not ready."
            )
            if release_blocker:
                issue_ids.append("matrix.stable-readiness.not-ready")
                extra_unwaivable_issue_ids.add("matrix.stable-readiness.not-ready")
                blocker_targets.append("stable-1.0.readiness-gate")
        elif main_status == "warn" or decision == "ready-with-allowed-limitations":
            status = "warn"
            release_blocker = False
            summary = "Stable 1.0 readiness is ready with bounded allowed limitations."
        elif stable_evidence_warn:
            status = "warn"
            release_blocker = False
            summary = "Stable 1.0 readiness evidence has warnings."
        else:
            status = "pass"
            release_blocker = False
            summary = "Stable 1.0 readiness evidence passed."
    elif not spec.evidence_ids() and not spec.all_gate_ids():
        status = "missing"
        release_blocker = False
        summary = "Matrix row has no evidence or gate inputs."
        issue_ids.append("matrix.row-inputs-missing")
    elif required_bad or gate_blockers:
        status = "fail"
        release_blocker = True
        summary = "Required evidence or an ecosystem gate is release-blocking."
    elif (
        required_skip_only
        and not required_warn
        and not optional_warn
        and not gate_warnings
    ):
        status = "skip"
        release_blocker = False
        summary = "Required evidence was intentionally skipped outside release-candidate mode."
    elif (
        required_warn
        or skipped_required_non_rc
        or optional_warn
        or gate_warnings
        or any(
            previous_statuses.get(evidence_id) == "pass" and status_value == "warn"
            for evidence_id, status_value in required_statuses.items()
        )
    ):
        status = "warn"
        release_blocker = False
        summary = "Required or optional evidence needs release-manager review."
    else:
        status = "pass"
        release_blocker = False
        summary = "Required evidence and referenced ecosystem gates passed."

    waiver_for_blocker = row_release_blocker_waiver(
        spec,
        waiver_context,
        settings.mode,
        issue_ids,
        blocker_targets,
        unwaivable_redaction_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    if release_blocker and waiver_for_blocker is not None:
        status = "warn"
        release_blocker = False
        summary = f"{summary} Waiver recorded: {waiver_for_blocker.reason}"
    waiver_records, waiver_ids = row_waivers(
        spec,
        evidence_entries,
        gate_entries,
        waiver_context,
        settings.mode,
        issue_ids,
        unwaivable_redaction_evidence_ids,
        extra_unwaivable_issue_ids,
    )
    if waiver_for_blocker is not None and waiver_for_blocker.id not in waiver_ids:
        waiver_records = sorted([*waiver_records, waiver_for_blocker], key=lambda record: record.id)
        waiver_ids = sorted([*waiver_ids, waiver_for_blocker.id])
    if waiver_ids and status == "pass":
        status = "warn"
        summary = "Active waiver is recorded for this row."

    previous_status, regression_status = regression_status_for_row(
        spec,
        status,
        release_blocker,
        previous_summary_present,
        previous_matrix_present,
        previous_row_statuses,
    )
    if stable_not_requested:
        previous_status = "pass"
        regression_status = "unchanged"
    if regression_status in {"regressed-warning", "regressed-blocker"} and status == "pass":
        status = "warn"
    gate_status_value = aggregate_status_values(
        list(gate_statuses.values()) + list(optional_gate_statuses.values()),
        missing_if_empty=bool(spec.gate_ids),
    )
    details: dict[str, Any] = {
        "currentEvidenceStatuses": required_statuses | optional_statuses,
        "previousEvidenceStatuses": previous_statuses,
        "gateStatuses": gate_statuses | optional_gate_statuses,
    }
    if spec.first_party_apps:
        details["firstPartyApps"] = list(spec.first_party_apps)
    if waiver_records:
        details["waiverReasons"] = safe_waiver_summaries(waiver_records)
    if spec.synthetic == "history":
        details["historyStatus"] = history_status
        details["previousMatrixPresent"] = previous_matrix_present
    if spec.synthetic == "redaction":
        details["redaction"] = redaction
    if stable_not_requested:
        details["notRequested"] = True
        details["required"] = False
    if unwaivable_redaction_evidence_ids:
        details["unwaivableRedactionEvidenceIds"] = sorted(unwaivable_redaction_evidence_ids)
    if extra_unwaivable_issue_ids:
        details["unwaivableIssueIds"] = sorted(extra_unwaivable_issue_ids)

    return {
        "id": spec.id,
        "category": spec.category,
        "title": spec.title,
        "requiredForReleaseCandidate": spec.required_for_release_candidate,
        "status": status,
        "previousStatus": previous_status,
        "regressionStatus": regression_status,
        "releaseBlocker": release_blocker,
        "summary": summary,
        "evidenceIds": list(spec.evidence_ids()),
        "requiredEvidenceIds": list(spec.required_evidence_ids),
        "optionalEvidenceIds": list(spec.optional_evidence_ids),
        "gateIds": list(spec.all_gate_ids()),
        "gateStatus": gate_status_value,
        "waiverIds": waiver_ids,
        "issueIds": sorted(dict.fromkeys(issue_ids)),
        "docs": list(spec.docs),
        "owner": spec.owner,
        "phase": spec.phase,
        "recommendation": row_recommendation(
            status,
            release_blocker,
            waiver_ids,
            missing_required,
            gate_blockers,
            previous_matrix_missing_warning,
        ),
        "details": details,
    }

def validate_matrix_coverage(
    settings: Settings,
    specs: list[MatrixRowSpec],
    evidence_entries: dict[str, dict[str, Any]],
    gate_entries: dict[str, dict[str, Any]],
    redaction: dict[str, bool],
) -> dict[str, Any]:
    mapped_required_evidence = {
        evidence_id for spec in specs for evidence_id in spec.required_evidence_ids
    }
    mapped_evidence = {evidence_id for spec in specs for evidence_id in spec.evidence_ids()}
    required_evidence = {
        evidence_id
        for evidence_id, entry in evidence_entries.items()
        if evidence_required(entry)
    }
    mapped_gates = {gate_id for spec in specs for gate_id in spec.all_gate_ids()}
    gate_ids = set(gate_entries)
    non_synthetic_specs = [spec for spec in specs if not spec.synthetic]
    rows_without_docs = [spec.id for spec in non_synthetic_specs if not spec.docs]
    rows_without_owners = [spec.id for spec in specs if not spec.owner]
    missing_doc_paths = sorted(
        {
            doc_path
            for spec in non_synthetic_specs
            for doc_path in spec.docs
            if not (settings.workspace_root / doc_path).is_file()
        }
    )
    first_party_apps = sorted(
        {
            app_id
            for spec in specs
            for app_id in spec.first_party_apps
        }
    )
    missing_first_party_apps = sorted(set(EXPECTED_FIRST_PARTY_APPS) - set(first_party_apps))
    missing_required_evidence_ids = sorted(mapped_required_evidence - set(evidence_entries))
    unmapped_required_evidence_ids = sorted(required_evidence - mapped_evidence)
    unmapped_gate_ids = sorted(gate_ids - mapped_gates)
    coverage_issue_ids: list[str] = []
    if missing_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-missing")
    if unmapped_required_evidence_ids:
        coverage_issue_ids.append("matrix.required-evidence-unmapped")
    if unmapped_gate_ids:
        coverage_issue_ids.append("matrix.ecosystem-gates-unmapped")
    if missing_first_party_apps:
        coverage_issue_ids.append("matrix.first-party-apps-uncovered")
    if rows_without_docs or missing_doc_paths:
        coverage_issue_ids.append("matrix.docs-uncovered")
    if not all(redaction.values()):
        coverage_issue_ids.append("matrix.redaction-failed")
    return {
        "requiredEvidenceCovered": not missing_required_evidence_ids and not unmapped_required_evidence_ids,
        "ecosystemGatesCovered": not unmapped_gate_ids,
        "firstPartyAppsCovered": not missing_first_party_apps,
        "docsCovered": not rows_without_docs and not missing_doc_paths,
        "redactionPassed": all(redaction.values()),
        "missingRequiredEvidenceIds": missing_required_evidence_ids,
        "unmappedRequiredEvidenceIds": unmapped_required_evidence_ids,
        "unmappedGateIds": unmapped_gate_ids,
        "rowsWithoutDocs": rows_without_docs,
        "rowsWithoutOwners": rows_without_owners,
        "missingDocPaths": missing_doc_paths,
        "coveredFirstPartyApps": first_party_apps,
        "missingFirstPartyApps": missing_first_party_apps,
        "issueIds": coverage_issue_ids,
    }

def matrix_coverage_waiver_state(
    coverage: dict[str, Any], context: WaiverContext, mode: str
) -> tuple[list[WaiverRecord], list[str], list[str]]:
    issue_ids = [str(issue_id) for issue_id in coverage.get("issueIds", []) if issue_id]
    waivable_issue_ids = [issue_id for issue_id in issue_ids if issue_id != "matrix.redaction-failed"]
    records_by_id: dict[str, WaiverRecord] = {}
    waived_issue_ids: list[str] = []
    row_waiver = active_waiver_for(
        context,
        "ecosystem-certification-matrix",
        ["release-certification.ecosystem-matrix"],
        mode,
    )
    for issue_id in waivable_issue_ids:
        waiver = row_waiver or active_waiver_for(
            context, "ecosystem-certification-matrix", [issue_id], mode
        )
        if waiver is None:
            waiver = active_waiver_for(context, issue_id, None, mode)
        if waiver is None:
            continue
        records_by_id[waiver.id] = waiver
        waived_issue_ids.append(issue_id)
    waived_issue_ids = sorted(dict.fromkeys(waived_issue_ids))
    unwaived_issue_ids = sorted(issue_id for issue_id in issue_ids if issue_id not in waived_issue_ids)
    return [records_by_id[waiver_id] for waiver_id in sorted(records_by_id)], waived_issue_ids, unwaived_issue_ids

def matrix_redaction_summary(summary_redaction: dict[str, Any] | None = None) -> dict[str, bool]:
    source = summary_redaction if isinstance(summary_redaction, dict) else {}
    return {
        "secretMaterialRedacted": bool(source.get("secretMaterialRedacted", True)),
        "formPasswordsRedacted": bool(source.get("formPasswordsRedacted", True)),
        "appProcessTokensRedacted": bool(source.get("appProcessTokensRedacted", True)),
        "browserSessionTokensRedacted": bool(source.get("browserSessionTokensRedacted", True)),
        "rawRequestBodiesExcluded": bool(source.get("rawRequestBodiesExcluded", True)),
        "rawFeedBodiesExcluded": bool(source.get("rawFeedBodiesExcluded", True)),
        "privateInsertUrisExcluded": bool(source.get("privateInsertUrisExcluded", True)),
        "signatureValuesRedacted": bool(source.get("signatureValuesRedacted", True)),
        "absolutePathsSanitized": bool(source.get("absolutePathsSanitized", True)),
    }

def matrix_categories(specs: list[MatrixRowSpec], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    row_counts = {category: 0 for category in MATRIX_CATEGORY_TITLES}
    for row in rows:
        category = str(row.get("category", ""))
        row_counts[category] = row_counts.get(category, 0) + 1
    categories: list[dict[str, Any]] = []
    for spec in specs:
        if any(category.get("id") == spec.category for category in categories):
            continue
        categories.append(
            {
                "id": spec.category,
                "title": MATRIX_CATEGORY_TITLES.get(spec.category, spec.category),
                "rowCount": row_counts.get(spec.category, 0),
            }
        )
    return categories

def build_ecosystem_matrix(
    settings: Settings,
    evidence: list[EvidenceItem],
    previous_summary: dict[str, Any] | None,
    history_comparison: dict[str, Any],
    ecosystem_gates: list[GateResult],
    waiver_context: WaiverContext,
    generated_at: str,
    summary_redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    specs = ecosystem_matrix_row_specs()
    evidence_entries = evidence_map_from_items(evidence)
    previous_evidence_entries = evidence_map_from_summary(previous_summary)
    gate_entries = {gate.id: gate.to_json() for gate in ecosystem_gates}
    previous_summary_present = previous_summary is not None
    previous_matrix_present = bool(
        isinstance(previous_summary, dict) and isinstance(previous_summary.get("ecosystemMatrix"), dict)
    )
    previous_row_statuses = previous_matrix_row_statuses(previous_summary)
    redaction = matrix_redaction_summary(summary_redaction)
    rows = [
        evaluate_matrix_row(
            spec,
            settings,
            evidence_entries,
            previous_evidence_entries,
            gate_entries,
            history_comparison,
            previous_summary_present,
            previous_matrix_present,
            previous_row_statuses,
            waiver_context,
            redaction,
        )
        for spec in specs
        ]
    coverage = validate_matrix_coverage(settings, specs, evidence_entries, gate_entries, redaction)
    coverage_waiver_records, waived_coverage_issue_ids, unwaived_coverage_issue_ids = matrix_coverage_waiver_state(
        coverage, waiver_context, settings.mode
    )
    coverage["waivedIssueIds"] = waived_coverage_issue_ids
    coverage["unwaivedIssueIds"] = unwaived_coverage_issue_ids
    coverage["coverageWaiverIds"] = [record.id for record in coverage_waiver_records]
    if coverage_waiver_records:
        coverage["waiverReasons"] = safe_waiver_summaries(coverage_waiver_records)
    for row in rows:
        if row["id"] == "ecosystem-certification-matrix" and coverage.get("issueIds"):
            row["issueIds"] = sorted(dict.fromkeys(row["issueIds"] + coverage["issueIds"]))
            row["details"]["coverageIssueIds"] = coverage["issueIds"]
            if waived_coverage_issue_ids:
                row["details"]["waivedCoverageIssueIds"] = waived_coverage_issue_ids
                row["details"]["waiverReasons"] = {
                    **(
                        row["details"].get("waiverReasons", {})
                        if isinstance(row["details"].get("waiverReasons"), dict)
                        else {}
                    ),
                    **safe_waiver_summaries(coverage_waiver_records),
                }
                row["waiverIds"] = sorted(
                    dict.fromkeys([*row.get("waiverIds", []), *coverage["coverageWaiverIds"]])
                )
            if unwaived_coverage_issue_ids and (
                settings.mode == "release-candidate" or coverage.get("redactionPassed") is False
            ):
                row["status"] = "fail"
                row["releaseBlocker"] = True
                row["summary"] = "Matrix coverage or redaction validation failed."
                row["recommendation"] = "Review failing evidence and rerun release certification."
            elif waived_coverage_issue_ids:
                row["status"] = "warn"
                row["releaseBlocker"] = False
                row["summary"] = "Matrix coverage validation produced waived warnings."
                row["recommendation"] = "Review waived evidence before release-candidate promotion."
            elif row["status"] == "pass":
                row["status"] = "warn"
                row["summary"] = "Matrix coverage validation produced warnings."
                row["recommendation"] = "Review warning evidence or record an approved waiver."
    counts = {status: 0 for status in CERT_STATUSES}
    release_blockers = 0
    waived_rows = 0
    for row in rows:
        if row["status"] == "skip" and row.get("requiredForReleaseCandidate") is False:
            counts["optionalSkips"] = counts.get("optionalSkips", 0) + 1
        else:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        if row.get("releaseBlocker"):
            release_blockers += 1
        if row.get("waiverIds"):
            waived_rows += 1
    counts["rows"] = len(rows)
    counts["releaseBlockers"] = release_blockers
    counts["waivedRows"] = waived_rows
    stable_required_blocking = required_stable_readiness_blocking(settings, rows)
    status = (
        "fail"
        if stable_required_blocking
        else matrix_status_from_counts(settings.mode, counts, coverage)
    )
    release_candidate_passed = status != "fail" and release_blockers == 0
    matrix_diffs = [
        {
            "rowId": row["id"],
            "previousStatus": row["previousStatus"],
            "currentStatus": row["status"],
            "regressionStatus": row["regressionStatus"],
        }
        for row in rows
        if row["regressionStatus"] in {"regressed-warning", "regressed-blocker", "new-row", "previous-missing"}
    ]
    matrix = {
        "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "kind": "ecosystem-certification-matrix",
        "mode": settings.mode,
        "status": status,
        "generatedAt": generated_at,
        "promotionDecision": (
            "block"
            if not release_candidate_passed
            else ("promote-with-warnings" if status == "warn" else "promote")
        ),
        "releaseCandidatePassed": release_candidate_passed,
        "workspaceRoot": "<repo>",
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "matrixPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "matrixReportPath": display_path(
            settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "historyComparisonPath": display_path(
            settings.out_dir / HISTORY_COMPARISON_FILE_NAME,
            settings.workspace_root,
            settings.out_dir,
        ),
        "previousSummaryPresent": previous_summary_present,
        "previousMatrixPresent": previous_matrix_present,
        "counts": counts,
        "coverage": coverage,
        "categories": matrix_categories(specs, rows),
        "rows": rows,
        "matrixDiffs": matrix_diffs,
        "redaction": redaction,
    }
    return dict(sanitize_value(matrix, settings.workspace_root, settings.out_dir))

def matrix_compact_summary(matrix: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(matrix, dict):
        return {
            "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            "status": "missing",
            "rowCount": 0,
            "releaseBlockerCount": 0,
            "coverage": {},
            "rowStatuses": {},
            "matrixDiffs": [],
        }
    rows = matrix.get("rows", [])
    row_statuses = {
        str(row.get("id")): str(row.get("status", "missing"))
        for row in rows
        if isinstance(row, dict) and row.get("id")
    } if isinstance(rows, list) else {}
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    return {
        "schemaVersion": matrix.get("schemaVersion", ECOSYSTEM_MATRIX_SCHEMA_VERSION),
        "status": matrix.get("status", "missing"),
        "rowCount": counts.get("rows", len(row_statuses)),
        "releaseBlockerCount": counts.get("releaseBlockers", 0),
        "coverage": matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {},
        "rowStatuses": row_statuses,
        "matrixDiffs": matrix.get("matrixDiffs", []) if isinstance(matrix.get("matrixDiffs"), list) else [],
    }

def stable_readiness_compact_summary(
    evidence: list[EvidenceItem],
    required: bool,
) -> dict[str, Any]:
    entries = evidence_map_from_items(evidence)
    main = entries.get("stable-1.0.readiness-gate")
    redaction = entries.get("stable-1.0.redaction")
    if not isinstance(main, dict):
        return {
            "status": "missing" if required else "skip",
            "decision": "not-attached",
            "stableReady": False,
            "required": required,
            "summary": (
                "Stable 1.0 readiness is required but not attached."
                if required
                else "Stable 1.0 readiness was not requested for this certification run."
            ),
        }
    details = evidence_details(main)
    redaction_details = evidence_details(redaction)
    return {
        "status": evidence_status(main),
        "decision": str(details.get("decision", "not-ready")),
        "stableReady": details.get("stableReady") is True,
        "required": required,
        "source": str(main.get("source", "")),
        "summary": str(main.get("summary", "")),
        "blockerCount": details.get("blockerCount", 0),
        "warningCount": details.get("warningCount", 0),
        "allowedLimitationCount": details.get("allowedLimitationCount", 0),
        "disallowedLimitationCount": details.get("disallowedLimitationCount", 0),
        "redactionStatus": evidence_status(redaction),
        "redactionFindingCount": redaction_details.get("findingCount", 0),
        "artifactRefs": details.get("artifactRefs", {}) if isinstance(details.get("artifactRefs"), dict) else {},
    }

def ecosystem_matrix_evidence(
    matrix: dict[str, Any],
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    status = normalize_evidence_status(str(matrix.get("status", "missing")))
    counts = matrix.get("counts", {}) if isinstance(matrix.get("counts"), dict) else {}
    coverage = matrix.get("coverage", {}) if isinstance(matrix.get("coverage"), dict) else {}
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            status,
            True,
            f"Ecosystem certification matrix status is {status}.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
                "rowCount": counts.get("rows", 0),
                "coverage": coverage,
                "redactionPassed": bool(coverage.get("redactionPassed", False)),
            },
        ),
        workspace_root,
        out_dir,
    )

def placeholder_ecosystem_matrix_evidence(workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return sanitize_evidence_item(
        EvidenceItem(
            "release-certification.ecosystem-matrix",
            "pass",
            True,
            "Ecosystem certification matrix generation is pending.",
            display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
            {
                "matrixPath": display_path(out_dir / ECOSYSTEM_MATRIX_FILE_NAME, workspace_root, out_dir),
                "matrixReportPath": display_path(
                    out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME,
                    workspace_root,
                    out_dir,
                ),
                "schemaVersion": ECOSYSTEM_MATRIX_SCHEMA_VERSION,
            },
        ),
        workspace_root,
        out_dir,
    )

def ecosystem_rc_gate_evidence(
    gate: GateResult | None,
    workspace_root: Path,
    out_dir: Path,
) -> EvidenceItem:
    if gate is None:
        return placeholder_ecosystem_rc_gate_evidence(workspace_root, out_dir)
    waiver_ids = gate_waiver_ids(gate)
    compact_details = {
        key: gate.details.get(key)
        for key in (
            "phase",
            "requiredEvidenceIds",
            "requiredGateIds",
            "failedEvidenceIds",
            "warningEvidenceIds",
            "missingEvidenceIds",
            "skippedEvidenceIds",
            "blockingGateIds",
            "warningGateIds",
            "waivedEvidenceIds",
            "waivedGateIds",
            "historyComparisonStatus",
            "liveNetworkRequired",
            "liveNetworkSatisfied",
            "networkScaleSoakSatisfied",
            "redactionPassed",
            "redactionFailureEvidenceIds",
            "firstPartyAppsCovered",
            "promotionReady",
        )
        if key in gate.details
    }
    if waiver_ids:
        compact_details["waiverIds"] = waiver_ids
    details = {
        "gateId": gate.id,
        "releaseBlocker": gate.release_blocker,
        "promotionReady": bool(gate.details.get("promotionReady", not gate.release_blocker)),
        "failedEvidenceCount": len(gate.details.get("failedEvidenceIds", [])),
        "missingEvidenceCount": len(gate.details.get("missingEvidenceIds", [])),
        "warningEvidenceCount": len(gate.details.get("warningEvidenceIds", [])),
        "blockingGateCount": len(gate.details.get("blockingGateIds", [])),
        "warningGateCount": len(gate.details.get("warningGateIds", [])),
        "waiverCount": len(waiver_ids),
        "details": compact_details,
    }
    return sanitize_evidence_item(
        EvidenceItem(
            ECOSYSTEM_RC_EVIDENCE_ID,
            gate.status,
            True,
            gate.summary,
            display_path(out_dir / SUMMARY_FILE_NAME, workspace_root, out_dir),
            details,
        ),
        workspace_root,
        out_dir,
    )

def placeholder_ecosystem_rc_gate_evidence(workspace_root: Path, out_dir: Path) -> EvidenceItem:
    return sanitize_evidence_item(
        EvidenceItem(
            ECOSYSTEM_RC_EVIDENCE_ID,
            "pass",
            True,
            "Ecosystem RC certification gate evaluation is pending.",
            display_path(out_dir / SUMMARY_FILE_NAME, workspace_root, out_dir),
            {
                "gateId": ECOSYSTEM_RC_GATE_ID,
                "phase": "phase-9",
                "promotionReady": False,
            },
        ),
        workspace_root,
        out_dir,
    )

def release_metadata_note_present(metadata: dict[str, Any], *keys: str) -> bool:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, bool) and value:
            return True
    return False

def summary_identity(
    summary: dict[str, Any] | None,
    workspace_root: Path,
    out_dir: Path,
    source: str = "",
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"source": source} if source else {}
    metadata = summary.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    git_sha = (
        metadata.get("gitCommit")
        or metadata.get("githubSha")
        or summary.get("gitSha")
        or summary.get("commit")
        or ""
    )
    release_version = (
        metadata.get("releaseVersion")
        or metadata.get("version")
        or summary.get("releaseVersion")
        or summary.get("version")
        or ""
    )
    identity = {
        "source": source,
        "generatedAt": summary.get("generatedAt", ""),
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }
    return {key: sanitize_value(value, workspace_root, out_dir) for key, value in identity.items()}

def current_identity(generated_at: str, metadata: dict[str, Any]) -> dict[str, Any]:
    git_sha = metadata.get("gitCommit") or metadata.get("githubSha") or ""
    release_version = metadata.get("releaseVersion") or metadata.get("version") or ""
    return {
        "generatedAt": generated_at,
        "gitSha": git_sha,
        "releaseVersion": release_version,
    }

def classify_evidence_diff(
    evidence_id: str,
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
    waiver_context: WaiverContext,
    mode: str,
) -> dict[str, Any]:
    previous_status = evidence_status(previous)
    current_status = evidence_status(current)
    previous_present = previous is not None
    current_present = current is not None
    current_required = evidence_required(current)
    previous_required = evidence_required(previous)
    if not previous_present and current_present:
        classification = "new"
    elif previous_present and not current_present:
        classification = "removed"
    elif status_severity(current_status) > status_severity(previous_status):
        classification = "regression"
    elif status_severity(current_status) < status_severity(previous_status):
        classification = "improvement"
    else:
        classification = "unchanged"

    issue_ids = [
        f"history.{classification}.{evidence_id}",
        f"history.evidence.{evidence_id}",
        f"evidence.{evidence_id}",
        *ecosystem_matrix_row_ids_for_evidence(evidence_id),
    ]
    waived = bool(current and evidence_details(current).get("waived"))
    unwaivable_redaction_findings = evidence_entry_has_unwaivable_redaction_findings(current)
    waiver = (
        None
        if unwaivable_redaction_findings
        else active_waiver_for(waiver_context, evidence_id, issue_ids, mode)
    )
    release_blocker = False
    reason = "Evidence status is unchanged."
    if classification == "new":
        reason = "New evidence item is present in the current certification."
        if current_required and current_status in {"fail", "missing", "skip"}:
            release_blocker = True
            reason = "New required evidence is not passing."
        elif current_required and current_status == "warn":
            reason = "New required evidence is warning."
    elif classification == "removed":
        reason = "Evidence item was present in the previous certification but is absent now."
        release_blocker = previous_required
    elif classification == "regression":
        reason = f"Evidence regressed from {previous_status} to {current_status}."
        if (previous_required or current_required) and previous_status == "pass" and current_status in {
            "fail",
            "missing",
            "skip",
        }:
            release_blocker = True
        elif previous_required or current_required:
            reason = f"Required evidence regressed from {previous_status} to {current_status}."
    elif classification == "improvement":
        reason = f"Evidence improved from {previous_status} to {current_status}."

    if waiver is not None or waived:
        release_blocker = False
        if waiver is not None:
            reason = f"{reason} Waiver recorded: {waiver.reason}"

    return {
        "id": evidence_id,
        "previousStatus": previous_status if previous_present else "missing",
        "currentStatus": current_status if current_present else "missing",
        "classification": classification,
        "requiredForReleaseCandidate": bool(current_required or previous_required),
        "releaseBlocker": release_blocker,
        "reason": reason,
        "unwaivableRedactionFindings": unwaivable_redaction_findings,
    }

def load_previous_summary(settings: Settings) -> tuple[dict[str, Any] | None, str, str]:
    history_dir = resolve_path(settings.workspace_root, settings.history_dir)
    path: Path | None = settings.previous_summary
    if path is None:
        candidate = history_dir / "latest-summary.json"
        if candidate.is_file():
            path = candidate
    if path is None:
        return None, "", ""
    source = display_path(path, settings.workspace_root, settings.out_dir)
    value = read_json(path)
    if value is None:
        if path.is_file():
            return None, source, f"Previous summary {source} is malformed."
        return None, source, f"Previous summary {source} is missing."
    contract_error = previous_summary_contract_error(value)
    if contract_error:
        return None, source, f"Previous summary {source} is invalid: {contract_error}"
    sanitized = sanitize_value(value, settings.workspace_root, settings.out_dir)
    return sanitized if isinstance(sanitized, dict) else None, source, ""

def previous_summary_contract_error(value: dict[str, Any]) -> str:
    if value.get("kind") == multi_node_beta_soak.PREVIOUS_CANDIDATE_SUMMARY_KIND:
        return "previous beta candidate summaries are upgrade evidence, not release-certification history baselines"
    if value.get("tool") != TOOL_NAME:
        return "not a release-certification summary"
    if value.get("schemaVersion") != SCHEMA_VERSION:
        return "unsupported schema version"
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return "missing evidence list"
    if not any(isinstance(entry, dict) and entry.get("id") for entry in evidence):
        return "evidence list has no evidence ids"
    return ""

def compare_history(
    settings: Settings,
    previous_summary: dict[str, Any] | None,
    previous_source: str,
    previous_error: str,
    current_evidence: list[EvidenceItem],
    generated_at: str,
    metadata: dict[str, Any],
    waiver_context: WaiverContext,
) -> dict[str, Any]:
    previous_identity = summary_identity(
        previous_summary, settings.workspace_root, settings.out_dir, previous_source
    )
    current = current_identity(generated_at, metadata)
    if previous_summary is None:
        if previous_error:
            status = "fail" if settings.mode == "release-candidate" or settings.require_history else "warn"
            summary = previous_error
        elif settings.require_history:
            status = "fail"
            summary = "Previous certified baseline is required but was not provided."
        elif settings.mode == "pr":
            status = "skip"
            summary = "Previous certified baseline was not provided."
        else:
            status = "warn"
            summary = "Previous certified baseline was not provided; historical regression context is unavailable."
        return {
            "version": 1,
            "status": status,
            "summary": summary,
            "previous": previous_identity,
            "current": current,
            "evidenceDiffs": [],
            "ecosystemGates": [],
            "waivers": [record.to_json() for record in waiver_context.records],
        }

    previous_evidence = evidence_map_from_summary(previous_summary)
    current_evidence_map = evidence_map_from_items(current_evidence)
    all_ids = sorted(set(previous_evidence) | set(current_evidence_map))
    diffs = [
        classify_evidence_diff(
            evidence_id,
            previous_evidence.get(evidence_id),
            current_evidence_map.get(evidence_id),
            waiver_context,
            settings.mode,
        )
        for evidence_id in all_ids
    ]
    has_blocker = any(diff["releaseBlocker"] for diff in diffs)
    has_warning = any(
        diff["classification"] in {"regression", "new", "removed"} and diff["currentStatus"] != "pass"
        for diff in diffs
    )
    status = "fail" if has_blocker else ("warn" if has_warning else "pass")
    return {
        "version": 1,
        "status": status,
        "summary": "Historical comparison completed." if status == "pass" else "Historical comparison found release-relevant changes.",
        "previous": previous_identity,
        "current": current,
        "evidenceDiffs": diffs,
        "ecosystemGates": [],
        "waivers": [record.to_json() for record in waiver_context.records],
    }

def gate_from_issues(gate_id: str, summary: str, failures: list[str], warnings: list[str], details: dict[str, Any]) -> GateResult:
    if failures:
        status = "fail"
        release_blocker = True
        message = f"{summary} Blockers: {'; '.join(failures)}"
    elif warnings:
        status = "warn"
        release_blocker = False
        message = f"{summary} Warnings: {'; '.join(warnings)}"
    else:
        status = "pass"
        release_blocker = False
        message = summary
    if failures:
        details["failures"] = failures
    if warnings:
        details["warnings"] = warnings
    issue_ids = [f"{gate_id}.{slugify_issue(issue)}" for issue in failures + warnings]
    if issue_ids:
        details["issueIds"] = issue_ids
    return GateResult(gate_id, status, release_blocker, message, details)

def add_evidence_issue(details: dict[str, Any], key: str, evidence_id: str) -> None:
    values = details.setdefault(key, [])
    if isinstance(values, list) and evidence_id not in values:
        values.append(evidence_id)

def slugify_issue(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "issue"

def evaluate_required_evidence_regressions(diffs: list[dict[str, Any]]) -> GateResult:
    failures: list[str] = []
    warnings: list[str] = []
    details = {"regressions": [], "newRequiredEvidence": [], "removedEvidence": []}
    for diff in diffs:
        classification = diff["classification"]
        required = bool(diff.get("requiredForReleaseCandidate"))
        current_status = diff["currentStatus"]
        if classification == "regression" and required:
            details["regressions"].append(diff)
            if diff.get("releaseBlocker"):
                failures.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
                if diff.get("unwaivableRedactionFindings"):
                    add_evidence_issue(details, "unwaivableFailureEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"{diff['id']} regressed from {diff['previousStatus']} to {current_status}")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "regression":
            details["regressions"].append(diff)
            warnings.append(f"Optional evidence {diff['id']} regressed")
            add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "new" and required:
            details["newRequiredEvidence"].append(diff)
            if current_status in {"fail", "missing", "skip"}:
                failures.append(f"New required evidence {diff['id']} is {current_status}")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
                if diff.get("unwaivableRedactionFindings"):
                    add_evidence_issue(details, "unwaivableFailureEvidenceIds", str(diff["id"]))
            elif current_status == "warn":
                warnings.append(f"New required evidence {diff['id']} is warning")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
        elif classification == "removed":
            details["removedEvidence"].append(diff)
            if required and diff.get("releaseBlocker"):
                failures.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "failureEvidenceIds", str(diff["id"]))
            elif required:
                warnings.append(f"Required evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
            else:
                warnings.append(f"Optional evidence {diff['id']} was removed")
                add_evidence_issue(details, "warningEvidenceIds", str(diff["id"]))
    return gate_from_issues(
        "ecosystem.required-evidence-regressions",
        "Required release-candidate evidence did not regress.",
        failures,
        warnings,
        details,
    )

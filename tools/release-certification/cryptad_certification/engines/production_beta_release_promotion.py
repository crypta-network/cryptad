"""Implementation segment for the promotion portion of ``production_beta_release.py``."""

from __future__ import annotations

def evaluate_promotion(state: PipelineState, summaries: dict[str, Any]) -> dict[str, Any]:
    settings = state.settings
    cert_summary = summaries.get("certification") if isinstance(summaries.get("certification"), dict) else None
    app_summary = summaries.get("appPlatform") if isinstance(summaries.get("appPlatform"), dict) else None
    live_summary = summaries.get("liveNetwork") if isinstance(summaries.get("liveNetwork"), dict) else None
    multi_node_summary = (
        summaries.get("multiNodeBetaSoak") if isinstance(summaries.get("multiNodeBetaSoak"), dict) else None
    )
    matrix_summary = summaries.get("matrix") if isinstance(summaries.get("matrix"), dict) else None
    third_party_intake_summary = (
        summaries.get("thirdPartyIntake") if isinstance(summaries.get("thirdPartyIntake"), dict) else None
    )
    app_evidence = evidence_by_id(app_summary)
    cert_evidence = evidence_by_id(cert_summary)
    all_evidence = {**app_evidence, **cert_evidence}
    intake_evidence = third_party_intake_evidence(app_evidence, cert_evidence, third_party_intake_summary)
    required_intake_evidence = (
        third_party_intake_required_evidence(third_party_intake_summary)
        if settings.require_third_party_intake
        else intake_evidence
    )
    gates: list[dict[str, Any]] = []

    def add_gate(gate_id: str, ok: bool, summary: str, source: str = "pipeline") -> None:
        gates.append({"id": gate_id, "status": "pass" if ok else "fail", "summary": summary, "source": source})

    add_gate(
        "artifact.signed-first-party-bundles",
        all((settings.out_dir / "build/staged-apps" / app_id / "cryptad-app.signature").is_file() for app_id in APP_IDS),
        "Signed sidecars are present for every first-party staged app.",
    )
    add_gate(
        "artifact.signed-first-party-catalog",
        (settings.out_dir / "catalog/first-party-catalog.properties").is_file()
        and (settings.out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE).is_file(),
        "Signed first-party catalog sidecars are present.",
    )
    receipt_count = len(list((settings.out_dir / "reviews/review-receipts").glob("*-review-receipt.properties")))
    add_gate(
        "artifact.first-party-review-receipts",
        receipt_count >= len(APP_IDS),
        f"Review receipts present: {receipt_count}/{len(APP_IDS)}.",
    )
    if settings.use_fixture_evidence and settings.mode != "developer-dry-run":
        add_gate(
            "fixture-evidence.strict-mode",
            False,
            "Fixture evidence cannot certify release-candidate or production-beta runs.",
        )

    for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS:
        item = all_evidence.get(evidence_id)
        ok = evidence_status_ok(item)
        add_gate(
            f"evidence.{evidence_id}",
            ok,
            str(item.get("summary", "Required evidence is missing.")) if isinstance(item, dict) else "Required evidence is missing.",
            "release-certification",
        )

    missing_or_failed_intake = [
        evidence_id
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS
        if not evidence_status_ok(required_intake_evidence.get(evidence_id))
    ]
    redaction_status = third_party_intake_redaction_status(
        third_party_intake_summary,
        required_intake_evidence,
    )
    has_intake_material = third_party_intake_summary is not None or bool(intake_evidence)
    add_gate(
        "third-party-intake.required-evidence",
        (
            not settings.require_third_party_intake
            or (
                third_party_intake_summary is not None
                and summary_status(third_party_intake_summary) == "pass"
                and not missing_or_failed_intake
            )
        ),
        (
            "Third-party app intake evidence is passing."
            if settings.require_third_party_intake
            else "Third-party app intake evidence is optional for this run."
        ),
        "third-party-intake",
    )
    add_gate(
        "third-party-intake.redaction",
        redaction_status == "pass" if has_intake_material or settings.require_third_party_intake else True,
        f"Third-party intake redaction status is {redaction_status}.",
        "third-party-intake",
    )
    if settings.mode in {"release-candidate", "production-beta"} and (
        settings.require_third_party_intake or third_party_intake_summary is not None
    ):
        add_gate(
            "third-party-intake.production-evidence",
            third_party_intake_summary is not None
            and not third_party_intake_summary_is_non_release(third_party_intake_summary),
            "Attached or required third-party intake evidence must not be marked non-release or non-production.",
            "third-party-intake",
        )

    if settings.require_sandbox_provider_tests:
        item = all_evidence.get("apphost.sandbox-provider")
        add_gate(
            "evidence.required-sandbox-provider-tests",
            evidence_status_ok(item),
            str(item.get("summary", "Sandbox provider evidence is required for this run."))
            if isinstance(item, dict)
            else "Sandbox provider evidence is required for this run.",
            "release-certification",
        )

    if settings.require_live_network:
        live_evidence = evidence_by_id(live_summary)
        for evidence_id in LIVE_NETWORK_REQUIRED_IDS:
            item = live_evidence.get(evidence_id)
            add_gate(
                f"live.{evidence_id}",
                isinstance(item, dict) and item.get("status") == "pass",
                str(item.get("summary", "Required live-network beta evidence is missing."))
                if isinstance(item, dict)
                else "Required live-network beta evidence is missing.",
                "live-network-beta-smoke",
            )
    elif settings.mode == "production-beta":
        add_gate(
            "live.production-beta-skip",
            False,
            "Live-network beta evidence was skipped for a production-beta run; the candidate is not promotion-ready.",
        )

    multi_node_compact = (
        compact_multi_node_summary_for_release(
            multi_node_summary,
            strict=settings.mode == "production-beta" and settings.require_multi_node_soak,
        )
        if isinstance(multi_node_summary, dict)
        else {
            "status": "missing",
            "promotionReady": False,
            "mode": settings.multi_node_mode or "config",
            "scenarioStatuses": {},
            "blockers": ["multi-node beta soak summary is missing"],
            "warnings": [],
            "redaction": {"status": "missing", "findings": []},
        }
    )
    if settings.require_multi_node_soak:
        multi_node_redaction = multi_node_compact.get("redaction", {})
        multi_node_redaction_status = (
            multi_node_redaction.get("status", "missing")
            if isinstance(multi_node_redaction, dict)
            else "missing"
        )
        add_gate(
            "multi-node-beta.soak",
            multi_node_compact.get("status") == "pass"
            and multi_node_compact.get("promotionReady") is True
            and multi_node_redaction_status == "pass",
            "Required multi-node beta soak and upgrade drill evidence is passing.",
            "multi-node-beta-soak",
        )
        scenario_statuses = multi_node_compact.get("scenarioStatuses", {})
        if not isinstance(scenario_statuses, dict):
            scenario_statuses = {}
        for scenario_id, evidence_id in multi_node_beta_soak.SCENARIO_EVIDENCE_IDS.items():
            add_gate(
                evidence_id,
                scenario_statuses.get(scenario_id) == "pass",
                f"{scenario_id} status is {scenario_statuses.get(scenario_id, 'missing')}.",
                "multi-node-beta-soak",
            )
        add_gate(
            "multi-node-beta.redaction",
            multi_node_redaction_status == "pass",
            f"Multi-node beta soak redaction status is {multi_node_redaction_status}.",
            "multi-node-beta-soak",
        )
        if settings.mode == "production-beta":
            previous_summary_value = read_json(settings.previous_summary) if settings.previous_summary else None
            previous_summary_errors = previous_candidate_summary_validation_errors(settings)
            current_catalog_channel, current_catalog_edition = current_catalog_channel_and_edition(
                settings,
                state.version,
            )
            previous_binding_errors = previous_candidate_upgrade_binding_errors(
                multi_node_compact,
                previous_summary_value,
                state.version,
                current_catalog_channel,
                current_catalog_edition,
            )
            add_gate(
                "multi-node-beta.previous-candidate-summary",
                not previous_summary_errors
                and not previous_binding_errors
                and scenario_statuses.get("upgrade-from-previous-candidate") == "pass"
                and previous_candidate_upgrade_ready(
                    multi_node_compact,
                    previous_summary_value,
                    state.version,
                    current_catalog_channel,
                    current_catalog_edition,
                ),
                (
                    "Production beta promotion requires a valid previous beta candidate summary, "
                    "passing previous-candidate upgrade drill evidence, app-data migration, "
                    "backup/restore, Social Inbox and Trust Graph migration, rollback, and "
                    "redacted support-bundle proof."
                ),
                "multi-node-beta-soak",
            )
            if previous_summary_errors:
                add_gate(
                    "multi-node-beta.previous-candidate-summary-validation",
                    False,
                    "Previous beta candidate summary validation failed: "
                    + "; ".join(previous_summary_errors[:5]),
                    "multi-node-beta-soak",
                )
            if previous_binding_errors:
                add_gate(
                    "multi-node-beta.previous-candidate-upgrade-binding",
                    False,
                    "Previous beta candidate upgrade evidence does not match supplied previous summary or current catalog: "
                    + "; ".join(previous_binding_errors[:5]),
                    "multi-node-beta-soak",
                )
            multi_node_mode = str(multi_node_compact.get("mode", "missing"))
            add_gate(
                "multi-node-beta.production-evidence-mode",
                multi_node_mode in {"hybrid", "live"}
                and not uses_self_test_multi_node_topology(settings)
                and not (settings.run_multi_node_soak and settings.multi_node_soak_config is None),
                "Production beta multi-node evidence must be attached from a real run or generated from an explicit non-self-test hybrid/live topology.",
                "multi-node-beta-soak",
            )

    cert_ok = isinstance(cert_summary, dict) and cert_summary.get("releaseCandidatePassed") is True
    add_gate("ecosystem.release-candidate-passed", cert_ok, "Ecosystem RC certification passed.", "release-certification")
    matrix_ok = (
        isinstance(matrix_summary, dict)
        and matrix_summary.get("status") in {"pass", "warn"}
        and int(matrix_summary.get("releaseBlockerCount", 0)) == 0
    )
    add_gate(
        "ecosystem.certification-matrix",
        matrix_ok,
        "Ecosystem certification matrix is present and has no release blockers.",
        "release-certification",
    )
    profile = state.signing_profile
    production_signing = bool(profile and profile.kind == "production" and not profile.generated_test_keys)
    if settings.mode == "production-beta":
        for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES:
            stage = state.pipeline_stages.get(stage_id, {})
            stage_status = stage.get("status", "missing") if isinstance(stage, dict) else "missing"
            add_gate(
                f"build.{stage_id}",
                stage_status == "pass",
                f"Pipeline stage {stage_id} status is {stage_status}.",
            )
        add_gate(
            "build.production-beta-complete",
            not production_build_skipped(settings) and all_required_production_pipeline_stages_completed(state),
            "Production beta promotion requires the Gradle build and first-party app staging/signing stages to run in this pipeline execution.",
        )
        add_gate(
            "workspace.clean-production-beta",
            state.workspace_status_known and not state.dirty_workspace,
            "Production beta promotion requires a clean git workspace.",
        )
        add_gate(
            "signing.production-keys",
            production_signing or settings.allow_test_signing_in_production,
            "Production beta uses configured production signing inputs or the explicit test-signing escape hatch.",
        )
    else:
        add_gate(
            "signing.non-production-labelled",
            bool(profile and profile.kind != "production"),
            "Dry-run or release-candidate artifacts are labelled non-production when test keys are used.",
        )

    failed = [gate for gate in gates if gate["status"] != "pass"]
    non_release = (
        settings.mode == "developer-dry-run"
        or settings.allow_test_signing_in_production
        or production_build_skipped(settings)
        or (settings.mode == "production-beta" and not all_required_production_pipeline_stages_completed(state))
        or state.dirty_workspace
        or not state.workspace_status_known
        or bool(profile and profile.kind != "production")
    )
    promotion_ready = not failed and settings.mode == "production-beta" and not non_release
    return {
        "status": "pass" if not failed else "fail",
        "promotionReady": promotion_ready,
        "nonRelease": non_release,
        "failedGateCount": len(failed),
        "gates": gates,
        "multiNodeBetaSoak": multi_node_compact,
        "legacyAdminFinalSurface": legacy_admin_final_surface_summary(all_evidence),
        "securityResponse": production_security_response_summary(all_evidence),
        "developerBetaProgram": developer_beta_program_summary(all_evidence),
        "publicBetaDocs": public_beta_docs_summary(all_evidence),
        "publicBetaSupportFeedback": public_beta_support_feedback_summary(all_evidence),
        "contentFormatRisk": content_format_risk_summary(app_evidence),
        "thirdPartyIntake": {
            "status": summary_status(third_party_intake_summary),
            "required": settings.require_third_party_intake,
            "summaryPath": "evidence/third-party-intake-summary.json",
            "redaction": redaction_status,
            "missingOrFailedEvidence": missing_or_failed_intake,
            "nonRelease": third_party_intake_summary_is_non_release(third_party_intake_summary),
        },
        "knownLimitations": [],
    }

def bad_artifact_name(rel_path: str) -> str | None:
    parts = re.split(r"[\\/]+", rel_path)
    for part in parts:
        if part.startswith("._"):
            return "AppleDouble file is not allowed"
        if part in BAD_ARTIFACT_NAMES:
            return f"{part} is not allowed"
        if part in BAD_ARTIFACT_DIRS:
            return f"{part} directory is not allowed"
        secret_reason = secret_artifact_name_reason(part)
        if secret_reason:
            return secret_reason
    return None

def secret_artifact_name_reason(name: str) -> str | None:
    leaf = name.strip()
    if not leaf:
        return None
    lower = leaf.lower()
    suffix = Path(lower).suffix
    collapsed = re.sub(r"[^a-z0-9]", "", lower)
    if suffix in FORBIDDEN_SECRET_ARTIFACT_SUFFIXES:
        return f"{suffix} key-store artifact is not allowed"
    if suffix not in CODE_LIKE_ARTIFACT_SUFFIXES and (
        SECRET_ARTIFACT_NAME_RE.search(lower) or collapsed in SECRET_ARTIFACT_COLLAPSED_NAMES
    ):
        return "secret-bearing artifact filename is not allowed"
    if suffix in SECRET_ARTIFACT_BINARY_SUFFIXES and any(
        marker in collapsed for marker in SECRET_ARTIFACT_BINARY_MARKERS
    ):
        return "binary secret/key artifact filename is not allowed"
    return None

def is_redacted_or_code_value(raw_value: str, allow_code_like: bool = True) -> bool:
    value = raw_value.strip().strip("'\"").rstrip(",;")
    if not value:
        return True
    normalized = value.lower()
    if normalized in {"==", "===", "!=", "!==", "&&", "||"}:
        return True
    if normalized in {"<redacted>", "redacted", "<masked>", "masked", "***", "null", "undefined"}:
        return True
    if (value.startswith("<") and value.endswith(">")) or normalized.startswith("<redacted") or normalized.startswith("${{"):
        return True
    if not allow_code_like:
        return False
    if "(" in value or ")" in value:
        return True
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) and not (
        len(value) >= 16 and any(character.isdigit() for character in value)
    ):
        return True
    if value.startswith("source.") or value.startswith("options.") or value.startswith("request."):
        return True
    return False

def is_unquoted_code_expression(match: re.Match[str]) -> bool:
    value = match.group(1).strip().rstrip(",;")
    if not value:
        return False
    value_start = match.start(1)
    if value_start > 0 and match.string[value_start - 1] in {"'", '"'}:
        return False
    return bool(re.fullmatch(r"(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*\([^;{}\"']*\)", value))

def add_value_findings(
    findings: list[dict[str, str]],
    text: str,
    rel_path: str,
    kind: str,
    regex: re.Pattern[str],
    allow_code_like: bool = True,
    allow_unquoted_code_expression: bool = False,
) -> None:
    for match in regex.finditer(text):
        if allow_unquoted_code_expression and is_unquoted_code_expression(match):
            continue
        value = match.group(1)
        if not is_redacted_or_code_value(value, allow_code_like=allow_code_like):
            findings.append({"path": rel_path, "kind": kind})
            return

def normalized_secret_env_value(name: str, raw_value: str) -> str | None:
    value = raw_value.strip()
    minimum_length = 1 if name == "CRYPTAD_CERT_FORM_PASSWORD" else MIN_SECRET_ENV_VALUE_LENGTH
    if len(value) < minimum_length:
        return None
    normalized = value.lower().strip("'\"")
    if normalized in {"<redacted>", "redacted", "<masked>", "masked", "***", "null", "undefined", "true", "false", "none", "unset"}:
        return None
    if (value.startswith("<") and value.endswith(">")) or normalized.startswith("<redacted") or normalized.startswith("${{"):
        return None
    return value

def protected_secret_environment_values(
    env: dict[str, str] | None = None, workspace_root: Path | None = None
) -> list[tuple[str, str]]:
    source = os.environ if env is None else env
    values: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(name: str, raw_value: str) -> None:
        value = normalized_secret_env_value(name, raw_value)
        if value is None or value in seen:
            return
        seen.add(value)
        values.append((name, value))

    def add_file_contents(name: str, raw_path: str) -> None:
        path = resolve_workspace_input_path(raw_path, workspace_root)
        if path is None:
            return
        try:
            content_bytes = path.read_bytes()
        except OSError:
            return
        if not content_bytes:
            return
        add(name, base64.b64encode(content_bytes).decode("ascii"))
        content = content_bytes.decode("utf-8", errors="ignore")
        add(name, content)
        for line in content.splitlines():
            add(name, line)

    for name, raw_value in source.items():
        if name in SECRET_ENV_INDIRECTION_NAMES:
            target_name = raw_value.strip()
            if target_name:
                add(target_name, source.get(target_name, ""))
            continue
        if name in SECRET_ENV_FILE_INDIRECTION_NAMES:
            add_file_contents(name, raw_value)
            continue
        if name.endswith(SECRET_ENV_VALUE_SKIP_SUFFIXES):
            continue
        if SECRET_ENV_VALUE_NAME_RE.search(name):
            add(name, raw_value)
    return values

def protected_secret_environment_byte_values(
    env: dict[str, str] | None = None, workspace_root: Path | None = None
) -> list[tuple[str, bytes]]:
    source = os.environ if env is None else env
    values: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for name, raw_value in source.items():
        if name not in SECRET_ENV_FILE_INDIRECTION_NAMES:
            continue
        path = resolve_workspace_input_path(raw_value, workspace_root)
        if path is None:
            continue
        try:
            value = path.read_bytes()
        except OSError:
            continue
        if len(value) < MIN_SECRET_ENV_VALUE_LENGTH or value in seen:
            continue
        seen.add(value)
        values.append((name, value))
    return values

def add_protected_secret_value_findings(
    findings: list[dict[str, str]], text: str, rel_path: str, workspace_root: Path | None
) -> None:
    for name, value in protected_secret_environment_values(workspace_root=workspace_root):
        if value in text:
            findings.append(
                {
                    "path": rel_path,
                    "kind": "protected-secret-value",
                    "detail": f"{name} value appeared unredacted.",
                }
            )
            return

def add_protected_secret_byte_findings(
    findings: list[dict[str, str]],
    window: bytes,
    rel_path: str,
    protected_values: list[tuple[str, bytes]],
) -> None:
    for name, value in protected_values:
        if value in window:
            findings.append(
                {
                    "path": rel_path,
                    "kind": "protected-secret-value",
                    "detail": f"{name} value appeared unredacted.",
                }
            )
            return

def contains_path_prefix(text: str, path_text: str) -> bool:
    normalized = path_text.rstrip("/\\")
    if not normalized or normalized in {"/", "\\"}:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(normalized)}(?=$|[/\\])")
    return bool(pattern.search(text))

def scan_text_for_findings(text: str, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    checks = (
        ("private-insert-uri", PRIVATE_INSERT_URI_RE),
        ("private-key", PRIVATE_KEY_RE),
        ("private-key-header", PRIVATE_KEY_HEADER_RE),
        ("bearer-token", BEARER_RE),
        ("url-userinfo", URL_USERINFO_RE),
        ("file-uri-local-path", FILE_URI_RE),
        ("windows-local-path", WINDOWS_PATH_RE),
        ("host-local-path", HOST_PATH_RE),
    )
    workspace_text = str(settings.workspace_root.resolve())
    home_text = str(Path.home().resolve())
    temp_text = tempfile.gettempdir()
    for kind, regex in checks:
        if regex.search(text):
            findings.append({"path": rel_path, "kind": kind})
    add_value_findings(findings, text, rel_path, "authorization-header", AUTH_HEADER_RE, allow_code_like=False)
    add_value_findings(
        findings,
        text,
        rel_path,
        "app-token",
        APP_TOKEN_VALUE_RE,
        allow_code_like=False,
        allow_unquoted_code_expression=True,
    )
    add_value_findings(findings, text, rel_path, "form-password", FORM_PASSWORD_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "raw-content-or-app-data", RAW_BODY_VALUE_RE, allow_code_like=False)
    add_value_findings(findings, text, rel_path, "ci-secret-value", CI_SECRET_VALUE_RE, allow_code_like=False)
    add_protected_secret_value_findings(findings, text, rel_path, settings.workspace_root)
    for kind, value in (("workspace-path", workspace_text), ("home-path", home_text), ("temp-path", temp_text)):
        if contains_path_prefix(text, value):
            findings.append({"path": rel_path, "kind": kind})
    return findings

def deduplicate_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    deduplicated: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for finding in findings:
        key = tuple(sorted((str(name), str(value)) for name, value in finding.items()))
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated

def iter_file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk

def iter_handle_chunks(handle: BinaryIO) -> Iterator[bytes]:
    while True:
        chunk = handle.read(TEXT_SCAN_CHUNK_BYTES)
        if not chunk:
            break
        yield chunk

def iter_prefixed_chunks(prefix: bytes, chunks: Iterable[bytes]) -> Iterator[bytes]:
    if prefix:
        yield prefix
    yield from chunks

def scan_decoded_byte_window(window: bytes, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings = scan_text_for_findings(window.decode("utf-8", errors="ignore"), rel_path, settings)
    if b"\x00" in window:
        nul_stripped_text = window.replace(b"\x00", b"").decode("utf-8", errors="ignore")
        findings.extend(scan_text_for_findings(nul_stripped_text, rel_path, settings))
    return findings

def scan_byte_chunks(chunks: Iterable[bytes], rel_path: str, settings: Settings) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    protected_byte_values = protected_secret_environment_byte_values(workspace_root=settings.workspace_root)
    tail = b""
    for chunk in chunks:
        window = tail + chunk
        add_protected_secret_byte_findings(findings, window, rel_path, protected_byte_values)
        findings.extend(scan_decoded_byte_window(window, rel_path, settings))
        tail = window[-TEXT_SCAN_OVERLAP_BYTES:]
    return deduplicate_findings(findings)

def scan_regular_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        return scan_byte_chunks(iter_file_chunks(path), rel_path, settings)
    except OSError:
        return [{"path": rel_path, "kind": "unreadable"}]

def archive_kind_for_name_or_prefix(name: str, prefix: bytes = b"") -> str | None:
    lower_name = name.lower()
    if Path(lower_name).suffix in ZIP_ARCHIVE_SUFFIXES or prefix.startswith(b"PK\x03\x04"):
        return "zip"
    if lower_name.endswith(TAR_GZ_ARCHIVE_SUFFIXES):
        return "tar-gz"
    return None

def is_compiled_archive_member(name: str) -> bool:
    suffixes = Path(name.lower()).suffixes
    return any(suffix in COMPILED_ARCHIVE_MEMBER_SUFFIXES for suffix in suffixes)

def scan_embedded_archive_bytes(data: bytes, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    if depth > MAX_NESTED_ARCHIVE_DEPTH:
        return [
            {
                "path": rel_path,
                "kind": "archive-nesting-too-deep",
                "detail": "Nested archive depth exceeds the production beta redaction scanner limit.",
            }
        ]
    kind = archive_kind_for_name_or_prefix(rel_path, data[:4])
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return scan_zip_members(archive, rel_path, settings, depth)
        except (EOFError, OSError, RuntimeError, zipfile.BadZipFile):
            return [{"path": rel_path, "kind": "invalid-zip"}]
    if kind == "tar-gz":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                return scan_tar_members(archive, rel_path, settings, depth)
        except (EOFError, OSError, tarfile.TarError):
            return [{"path": rel_path, "kind": "invalid-tar"}]
    return scan_byte_chunks([data], rel_path, settings)

def scan_zip_members(zip_archive: zipfile.ZipFile, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for info in zip_archive.infolist():
        member_rel = f"{rel_path}!/{info.filename}"
        reason = bad_artifact_name(info.filename)
        if reason:
            findings.append({"path": member_rel, "kind": "forbidden-zip-entry", "detail": reason})
        if info.is_dir():
            continue
        try:
            with zip_archive.open(info) as member:
                prefix = member.read(4)
                archive_kind = archive_kind_for_name_or_prefix(info.filename, prefix)
                if archive_kind:
                    findings.extend(
                        scan_embedded_archive_bytes(prefix + member.read(), member_rel, settings, depth + 1)
                    )
                elif is_compiled_archive_member(info.filename):
                    continue
                else:
                    findings.extend(
                        scan_byte_chunks(iter_prefixed_chunks(prefix, iter_handle_chunks(member)), member_rel, settings)
                    )
        except (EOFError, NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile):
            findings.append({"path": member_rel, "kind": "unreadable-zip-entry"})
    return findings

def scan_zip_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            return scan_zip_members(archive, rel_path, settings, 0)
    except (EOFError, OSError, zipfile.BadZipFile):
        return [{"path": rel_path, "kind": "invalid-zip"}]

def scan_tar_members(tar_archive: tarfile.TarFile, rel_path: str, settings: Settings, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for member in tar_archive.getmembers():
        member_rel = member.name if not rel_path else f"{rel_path}!/{member.name}"
        reason = bad_artifact_name(member.name)
        if reason:
            findings.append({"path": member_rel, "kind": "forbidden-tar-entry", "detail": reason})
        if member.isdir():
            continue
        if not member.isfile():
            findings.append(
                {
                    "path": member_rel,
                    "kind": "forbidden-tar-entry",
                    "detail": "Only regular files and directories are allowed in production beta archives.",
                }
            )
            continue
        extracted = tar_archive.extractfile(member)
        if extracted is None:
            continue
        try:
            prefix = extracted.read(4)
            archive_kind = archive_kind_for_name_or_prefix(member.name, prefix)
            if archive_kind:
                findings.extend(scan_embedded_archive_bytes(prefix + extracted.read(), member_rel, settings, depth + 1))
            elif is_compiled_archive_member(member.name):
                continue
            else:
                findings.extend(
                    scan_byte_chunks(iter_prefixed_chunks(prefix, iter_handle_chunks(extracted)), member_rel, settings)
                )
        except (EOFError, NotImplementedError, OSError, RuntimeError, tarfile.TarError):
            findings.append({"path": member_rel, "kind": "unreadable-tar-entry"})
    return findings

def scan_tar_gz_file(path: Path, rel_path: str, settings: Settings) -> list[dict[str, str]]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            return scan_tar_members(archive, rel_path, settings, 0)
    except (EOFError, OSError, tarfile.TarError):
        return [{"path": rel_path, "kind": "invalid-tar"}]

def scan_tree(root: Path, settings: Settings, include_dist: bool = False) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        rel_path = path.relative_to(root).as_posix()
        reason = bad_artifact_name(rel_path)
        if reason:
            findings.append({"path": rel_path, "kind": "forbidden-path", "detail": reason})
        if path.is_symlink():
            findings.append(
                {
                    "path": rel_path,
                    "kind": "forbidden-symlink",
                    "detail": "Symlinks are not allowed in production beta artifacts.",
                }
            )
            continue
        if path.is_dir():
            continue
        if not include_dist and rel_path.startswith("dist/"):
            continue
        if not path.is_file():
            findings.append(
                {
                    "path": rel_path,
                    "kind": "forbidden-special-file",
                    "detail": "Only regular files and directories are allowed in production beta artifacts.",
                }
            )
            continue
        if path.suffix.lower() in ZIP_ARCHIVE_SUFFIXES:
            findings.extend(scan_zip_file(path, rel_path, settings))
        elif rel_path.lower().endswith(TAR_GZ_ARCHIVE_SUFFIXES):
            findings.extend(scan_tar_gz_file(path, rel_path, settings))
        else:
            findings.extend(scan_regular_file(path, rel_path, settings))
    return findings

def release_redaction_report(findings: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "status": "pass" if not findings else "fail",
        "scannedRoot": "<release-out>",
        "findingCount": len(findings),
        "findings": findings,
    }

def scan_tarball(path: Path, settings: Settings) -> list[dict[str, str]]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            return scan_tar_members(archive, "", settings, 0)
    except (OSError, tarfile.TarError):
        return [{"path": path.name, "kind": "invalid-tar"}]

def render_markdown_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# Production Beta Release Summary",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Version: `{summary['version']}`",
        f"- Status: `{summary['status']}`",
        f"- Promotion ready: `{str(summary['promotionReady']).lower()}`",
        f"- Non-release: `{str(summary['nonRelease']).lower()}`",
        f"- Dirty workspace: `{str(summary.get('dirtyWorkspace', False)).lower()}`",
        f"- Catalog channel: `{summary['catalogChannel']}`",
        f"- Signing profile: `{summary['signingProfile']['kind'] if summary.get('signingProfile') else 'missing'}`",
        f"- Redaction: `{summary['redaction']['status']}`",
        "",
        "## Artifacts",
        "",
    ]
    for name, path in summary.get("artifacts", {}).items():
        lines.append(f"- `{name}`: `{path}`")
    go_no_go = summary.get("goNoGo", {})
    if isinstance(go_no_go, dict) and go_no_go:
        lines.extend(["", "## Go/No-Go Dashboard", ""])
        lines.append(f"- Decision: `{go_no_go.get('decision', 'pending')}`")
        lines.append(f"- Basis: `{go_no_go.get('basis', 'missing')}`")
        lines.append(f"- Dashboard JSON: `{go_no_go.get('dashboardJson', GO_NO_GO_DASHBOARD_JSON)}`")
        lines.append(
            f"- Dashboard Markdown: `{go_no_go.get('dashboardMarkdown', GO_NO_GO_DASHBOARD_MARKDOWN)}`"
        )
        lines.append(f"- Redaction report: `{go_no_go.get('redactionReport', GO_NO_GO_REDACTION_REPORT)}`")
        lines.append(f"- Waivers used: `{go_no_go.get('waiversUsed', 0)}`")
    stable_readiness = summary.get("stableReadiness", {})
    if isinstance(stable_readiness, dict) and stable_readiness:
        lines.extend(["", "## Stable 1.0 Readiness", ""])
        lines.append(f"- Required: `{str(stable_readiness.get('required', False)).lower()}`")
        lines.append(f"- Status: `{stable_readiness.get('status', 'missing')}`")
        lines.append(f"- Decision: `{stable_readiness.get('decision', 'not-ready')}`")
        lines.append(f"- Stable ready: `{str(stable_readiness.get('stableReady', False)).lower()}`")
        lines.append(f"- Blockers: `{stable_readiness.get('blockerCount', 0)}`")
        lines.append(f"- Warnings: `{stable_readiness.get('warningCount', 0)}`")
        lines.append(f"- Allowed limitations: `{stable_readiness.get('allowedLimitationCount', 0)}`")
        lines.append(f"- Disallowed limitations: `{stable_readiness.get('disallowedLimitationCount', 0)}`")
        lines.append(f"- Redaction: `{stable_readiness.get('redactionStatus', 'missing')}`")
        lines.append(f"- Report: `{stable_readiness.get('reportPath', STABLE_READINESS_REPORT_MARKDOWN)}`")
    multi_node = summary.get("multiNodeBetaSoak", {})
    if isinstance(multi_node, dict) and multi_node:
        lines.extend(["", "## Multi-node Beta Soak", ""])
        lines.append(f"- Status: `{multi_node.get('status', 'missing')}`")
        lines.append(f"- Mode: `{multi_node.get('mode', 'missing')}`")
        lines.append(
            f"- Promotion ready: `{str(multi_node.get('promotionReady', False)).lower()}`"
        )
        scenario_statuses = multi_node.get("scenarioStatuses", {})
        if isinstance(scenario_statuses, dict):
            for scenario_id in sorted(scenario_statuses):
                lines.append(f"- `{scenario_id}`: `{scenario_statuses[scenario_id]}`")
        for blocker in multi_node.get("blockers", []):
            lines.append(f"- Blocker: {blocker}")
        for warning in multi_node.get("warnings", []):
            lines.append(f"- Warning: {warning}")
    developer_beta = summary.get("developerBetaProgram", {})
    if isinstance(developer_beta, dict) and developer_beta:
        lines.extend(["", "## Developer Beta Program", ""])
        lines.append(f"- Status: `{developer_beta.get('status', 'missing')}`")
        lines.append(f"- Sample app flow: `{developer_beta.get('sampleAppFlow', 'missing')}`")
        lines.append(f"- Docs: `{developer_beta.get('docs', 'missing')}`")
        lines.append(
            f"- Submission checklist: `{developer_beta.get('submissionChecklist', 'missing')}`"
        )
        lines.append(
            f"- Compatibility window: `{developer_beta.get('compatibilityWindow', 'missing')}`"
        )
        lines.append(f"- Feedback workflow: `{developer_beta.get('feedbackWorkflow', 'missing')}`")
        lines.append(f"- Redaction: `{developer_beta.get('redaction', 'missing')}`")
        blockers = developer_beta.get("blockers", [])
        if isinstance(blockers, list):
            lines.append(f"- Blocker count: `{len(blockers)}`")
    public_beta_docs = summary.get("publicBetaDocs", {})
    if isinstance(public_beta_docs, dict) and public_beta_docs:
        lines.extend(["", "## Public Beta Docs", ""])
        lines.append(f"- Status: `{public_beta_docs.get('status', 'missing')}`")
        lines.append(
            f"- Onboarding front door: `{public_beta_docs.get('docsOnboarding', 'missing')}`"
        )
        lines.append(f"- User guide: `{public_beta_docs.get('userGuide', 'missing')}`")
        lines.append(
            f"- Developer quickstart: `{public_beta_docs.get('developerQuickstart', 'missing')}`"
        )
        lines.append(
            f"- Troubleshooting: `{public_beta_docs.get('troubleshooting', 'missing')}`"
        )
        lines.append(
            f"- Security reporting: `{public_beta_docs.get('securityReporting', 'missing')}`"
        )
        lines.append(f"- Limitations: `{public_beta_docs.get('limitations', 'missing')}`")
        lines.append(
            f"- Links and redaction: `{public_beta_docs.get('linksRedaction', 'missing')}`"
        )
        blockers = public_beta_docs.get("blockers", [])
        if isinstance(blockers, list):
            lines.append(f"- Blocker count: `{len(blockers)}`")
    support_feedback = summary.get("publicBetaSupportFeedback", {})
    if isinstance(support_feedback, dict) and support_feedback:
        lines.extend(["", "## Public Beta Support Feedback", ""])
        lines.append(f"- Status: `{support_feedback.get('status', 'missing')}`")
        lines.append(f"- Docs: `{support_feedback.get('docs', 'missing')}`")
        lines.append(
            f"- Issue templates: `{support_feedback.get('issueTemplates', 'missing')}`"
        )
        lines.append(
            f"- Known issues: `{support_feedback.get('knownIssuesTracker', 'missing')}`"
        )
        lines.append(
            f"- Feedback to backlog: `{support_feedback.get('feedbackToBacklog', 'missing')}`"
        )
        lines.append(
            f"- Release notes template: `{support_feedback.get('releaseNotesTemplate', 'missing')}`"
        )
        lines.append(
            f"- Support bundle guidance: `{support_feedback.get('supportBundleGuidance', 'missing')}`"
        )
        lines.append(
            f"- Security handoff: `{support_feedback.get('securityHandoff', 'missing')}`"
        )
        lines.append(
            f"- Redaction fixtures: `{support_feedback.get('redactionFixtures', 'missing')}`"
        )
        blockers = support_feedback.get("blockers", [])
        if isinstance(blockers, list):
            lines.append(f"- Blocker count: `{len(blockers)}`")
    third_party_intake = summary.get("thirdPartyIntake", {})
    if isinstance(third_party_intake, dict) and third_party_intake:
        lines.extend(["", "## Third-Party Intake", ""])
        lines.append(f"- Required: `{str(third_party_intake.get('required', False)).lower()}`")
        lines.append(f"- Status: `{third_party_intake.get('status', 'missing')}`")
        lines.append(f"- Redaction: `{third_party_intake.get('redaction', 'missing')}`")
        lines.append(f"- Non-release: `{str(third_party_intake.get('nonRelease', False)).lower()}`")
    content_format_risk = summary.get("contentFormatRisk", {})
    if isinstance(content_format_risk, dict) and content_format_risk:
        lines.extend(["", "## Content-Format Risk", ""])
        lines.append(f"- Evidence: `{content_format_risk.get('evidenceId', 'missing')}`")
        lines.append(f"- Status: `{content_format_risk.get('status', 'missing')}`")
        lines.append(f"- Severity: `{content_format_risk.get('severity', 'missing')}`")
        profiles = content_format_risk.get("profileIds", [])
        if isinstance(profiles, list):
            lines.append(f"- Profiles: `{','.join(str(profile) for profile in profiles)}`")
        failed_checks = content_format_risk.get("failedChecks", [])
        if isinstance(failed_checks, list):
            lines.append(f"- Failed checks: `{','.join(str(check) for check in failed_checks) or 'none'}`")
        lines.append(
            "- Raw content included: "
            f"`{str(content_format_risk.get('rawContentIncluded', True)).lower()}`"
        )
        lines.append(
            "- Raw signatures included: "
            f"`{str(content_format_risk.get('rawSignaturesIncluded', True)).lower()}`"
        )
    lines.extend(["", "## Failed Gates", ""])
    failed = [gate for gate in summary["promotion"]["gates"] if gate["status"] != "pass"]
    if not failed:
        lines.append("No failed gates.")
    else:
        for gate in failed:
            lines.append(f"- `{gate['id']}`: {gate['summary']}")
    legacy_admin = summary["promotion"].get("legacyAdminFinalSurface", {})
    if isinstance(legacy_admin, dict) and legacy_admin:
        lines.extend(["", "## Legacy Admin Wave 5", ""])
        lines.append(
            f"- Removal Wave 5 evidence: `{legacy_admin.get('removalWave5Status', 'missing')}`"
        )
        lines.append(
            "- Final admin surface evidence: "
            f"`{legacy_admin.get('finalAdminSurfaceStatus', 'missing')}`"
        )
        lines.append(
            f"- Browse retained evidence: `{legacy_admin.get('browseRetainedStatus', 'missing')}`"
        )
        lines.append(
            "- Emergency fallback evidence: "
            f"`{legacy_admin.get('emergencyFallbackStatus', 'missing')}`"
        )
        lines.append(
            "- Wave 5 promoted route ids: "
            f"`{','.join(legacy_admin.get('waveFivePromotedRouteIds', [])) or 'none'}`"
        )
    security_response = summary["promotion"].get("securityResponse", {})
    if isinstance(security_response, dict) and security_response:
        lines.extend(["", "## Security Response", ""])
        lines.append(f"- Runbook evidence: `{security_response.get('status', 'missing')}`")
        lines.append(f"- Runbook status: `{security_response.get('runbookStatus', 'missing')}`")
        lines.append(
            "- Advisory lifecycle: "
            f"`{security_response.get('advisoryLifecycleStatus', 'missing')}`"
        )
        lines.append(
            "- Reviewer compromise drill: "
            f"`{security_response.get('reviewerCompromiseDrillStatus', 'missing')}`"
        )
        lines.append(
            "- Catalog key rotation drill: "
            f"`{security_response.get('catalogKeyRotationDrillStatus', 'missing')}`"
        )
        lines.append(
            "- App signing key compromise drill: "
            f"`{security_response.get('appSigningKeyCompromiseDrillStatus', 'missing')}`"
        )
        lines.append(
            "- Emergency catalog update drill: "
            f"`{security_response.get('emergencyCatalogUpdateDrillStatus', 'missing')}`"
        )
        lines.append(
            f"- Support redaction: `{security_response.get('supportRedactionStatus', 'missing')}`"
        )
        lines.append(
            "- Security release notes template: "
            f"`{security_response.get('securityReleaseNotesTemplateStatus', 'missing')}`"
        )
        counts = security_response.get("counts")
        if isinstance(counts, dict):
            lines.append(f"- Required drills: `{counts.get('required', 0)}`")
            lines.append(f"- Passed drills: `{counts.get('passed', 0)}`")
            lines.append(f"- Failed drills: `{counts.get('failed', 0)}`")
            lines.append(f"- Missing drills: `{counts.get('missing', 0)}`")
            lines.append(f"- Stale drills: `{counts.get('stale', 0)}`")
            lines.append(f"- Redaction: `{security_response.get('redactionStatus', 'missing')}`")
        for label, key in (
            ("Failed drills", "failedScenarios"),
            ("Missing drills", "missingScenarios"),
            ("Stale drills", "staleScenarios"),
            ("Malformed drills", "malformedScenarios"),
        ):
            values = security_response.get(key)
            if isinstance(values, list) and values:
                lines.append(f"- {label}: `{','.join(str(value) for value in values)}`")
        for blocker in security_response.get("blockers", []):
            lines.append(f"- Blocker: {blocker}")
        for warning in security_response.get("warnings", []):
            lines.append(f"- Warning: {warning}")
    lines.extend(["", "## Known Limitations", ""])
    for limitation in summary["promotion"].get("knownLimitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)

def dist_bundle_path(settings: Settings, version: str) -> Path:
    return settings.out_dir / "dist" / f"crypta-production-beta-{version}.tar.gz"

def dist_checksums_path(settings: Settings) -> Path:
    return settings.out_dir / "dist" / "checksums.txt"

def reset_output_subtree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.mkdir(parents=True, exist_ok=True)

def reset_dist_dir(settings: Settings) -> None:
    reset_output_subtree(settings.out_dir / "dist")

def reset_release_output_roots(settings: Settings) -> None:
    for root_name in RELEASE_OUTPUT_ROOTS:
        reset_output_subtree(settings.out_dir / root_name)

def remove_dist_bundle(settings: Settings, archive: Path) -> None:
    for path in (archive, dist_checksums_path(settings)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

def create_dist_bundle(settings: Settings, version: str) -> Path:
    dist_dir = settings.out_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dist_bundle_path(settings, version)

    def tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo:
        reason = bad_artifact_name(info.name)
        if reason:
            raise ReleaseArtifactError(f"dist archive would include forbidden artifact {info.name}: {reason}")
        if info.issym() or info.islnk():
            raise ReleaseArtifactError(f"dist archive would include a link entry, which is not allowed: {info.name}")
        if info.isdev():
            raise ReleaseArtifactError(f"dist archive would include a device entry, which is not allowed: {info.name}")
        return info

    with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for root_name in RELEASE_OUTPUT_ROOTS:
            root_path = settings.out_dir / root_name
            if root_path.exists():
                archive.add(root_path, arcname=root_name, recursive=True, filter=tar_filter)
    checksums = dist_checksums_path(settings)
    checksum_lines = [f"{sha256_file(tar_path)}  {tar_path.name}"]
    write_text(checksums, "\n".join(checksum_lines) + "\n")
    return tar_path

def build_final_summary(
    state: PipelineState,
    promotion: dict[str, Any],
    redaction_report: dict[str, Any],
    archive: Path | None,
) -> dict[str, Any]:
    settings = state.settings
    profile = state.signing_profile
    artifacts = {
        "releaseConfig": "inputs/release-config.json",
        "firstPartyMaintenancePolicy": "inputs/first-party-app-maintenance-policy.json",
        "firstPartyBetaReadiness": "inputs/first-party-app-beta-readiness.json",
        "catalog": "catalog/first-party-catalog.properties",
        "catalogSignature": f"catalog/{CANONICAL_CATALOG_SIGNATURE}",
        "catalogSignatureAlias": f"catalog/{RELEASE_CATALOG_SIGNATURE_ALIAS}",
        "channelMetadata": "catalog/channel-metadata.json",
        "reviewReceipts": "reviews/review-receipts/",
        "appPlatformSmoke": "evidence/app-platform-smoke.json",
        "securityDrillsSummary": "security-drills/security-drills-summary.json",
        "securityDrillsEvidence": "evidence/security-drills-summary.json",
        "multiNodeBetaSoak": "evidence/multi-node-beta-soak.json",
        "ecosystemCertification": "evidence/ecosystem-rc-certification.json",
        "thirdPartyIntake": "evidence/third-party-intake-summary.json",
        "redactionReport": "reports/redaction-report.json",
        "goNoGoDashboard": GO_NO_GO_DASHBOARD_JSON,
        "goNoGoDashboardReport": GO_NO_GO_DASHBOARD_MARKDOWN,
        "goNoGoRedactionReport": GO_NO_GO_REDACTION_REPORT,
    }
    if security_release_notes_draft_path(settings).is_file():
        artifacts["securityReleaseNotesDraft"] = "security/security-release-notes-draft.md"
    if archive is not None:
        artifacts["distArchive"] = f"dist/{archive.name}"
        artifacts["checksums"] = "dist/checksums.txt"
    command_and_redaction_ok = not state.failures and redaction_report["status"] == "pass"
    if settings.mode == "developer-dry-run":
        status = "pass" if command_and_redaction_ok else "fail"
    else:
        status = "pass" if command_and_redaction_ok and promotion["status"] == "pass" else "fail"
    summary_promotion_ready = bool(command_and_redaction_ok and status == "pass" and promotion["promotionReady"])
    final_promotion = dict(promotion)
    final_promotion["promotionReady"] = summary_promotion_ready
    previous_candidate_metadata = previous_candidate_metadata_for_release(state, redaction_report)
    content_format_risk = final_promotion.get(
        "contentFormatRisk",
        content_format_risk_summary({}),
    )
    multi_node_compact = dict(final_promotion.get("multiNodeBetaSoak", {}))
    if not multi_node_compact:
        multi_node_compact = {
            "status": "missing",
            "promotionReady": False,
            "mode": settings.multi_node_mode or "config",
            "scenarioStatuses": {},
            "blockers": [],
            "warnings": [],
        }
    multi_node_compact["summaryPath"] = artifacts["multiNodeBetaSoak"]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generatedAt": utc_now(),
        "startedAt": state.started_at,
        "mode": settings.mode,
        "releaseId": state.settings.release_id or f"cryptad-beta-{state.version}",
        "version": state.version,
        "artifactBaseUri": settings.artifact_base_uri,
        "status": status,
        "promotionReady": summary_promotion_ready,
        "nonRelease": promotion["nonRelease"],
        "workspaceStatusKnown": state.workspace_status_known,
        "dirtyWorkspace": state.dirty_workspace,
        "catalogChannel": settings.catalog_channel,
        "signingProfile": None
        if profile is None
        else {
            "kind": profile.kind,
            "generatedTestKeys": profile.generated_test_keys,
            "appKeyId": profile.app_key_id,
            "reviewerKeyId": profile.reviewer_key_id,
            "privateKeyMaterialIncluded": False,
        },
        "certificationExitCode": state.certification_exit_code,
        "pipelineStages": state.pipeline_stages,
        "warnings": state.warnings,
        "failures": state.failures,
        "multiNodeBetaSoak": multi_node_compact,
        "developerBetaProgram": final_promotion.get(
            "developerBetaProgram",
            {"status": "missing"},
        ),
        "publicBetaDocs": final_promotion.get("publicBetaDocs", {"status": "missing"}),
        "publicBetaSupportFeedback": final_promotion.get(
            "publicBetaSupportFeedback",
            {"status": "missing"},
        ),
        "thirdPartyIntake": final_promotion.get(
            "thirdPartyIntake",
            {"status": "missing", "required": settings.require_third_party_intake},
        ),
        "contentFormatRisk": content_format_risk,
        "promotion": final_promotion,
        "redaction": redaction_report,
        "previousCandidateMetadata": previous_candidate_metadata,
        "commands": [dataclasses.asdict(command) for command in state.commands],
        "artifacts": artifacts,
        "goNoGo": {
            "decision": "pending",
            "basis": "dashboard-not-generated",
            "dashboardJson": GO_NO_GO_DASHBOARD_JSON,
            "dashboardMarkdown": GO_NO_GO_DASHBOARD_MARKDOWN,
            "redactionReport": GO_NO_GO_REDACTION_REPORT,
            "blockingGateIds": [],
            "failedGateCount": int(final_promotion.get("failedGateCount", 0)),
            "redactionStatus": redaction_report.get("status", "missing"),
            "releaseArtifactRedactionStatus": redaction_report.get("status", "missing"),
            "nonRelease": final_promotion.get("nonRelease", True),
        },
    }

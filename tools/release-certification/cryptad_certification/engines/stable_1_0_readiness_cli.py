"""Implementation segment for the cli portion of ``stable_1_0_readiness.py``."""

from __future__ import annotations

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline Stable 1.0 readiness fixture tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--generated-at",
        default="",
        help="Set the output generatedAt timestamp; freshness validation always uses the current UTC time.",
    )
    parser.add_argument("--production-beta-summary", type=Path)
    parser.add_argument("--go-no-go-summary", type=Path)
    parser.add_argument("--release-certification-summary", type=Path)
    parser.add_argument("--ecosystem-matrix", type=Path)
    parser.add_argument("--app-platform-summary", type=Path)
    parser.add_argument("--multi-node-soak-summary", type=Path)
    parser.add_argument("--multi-node-beta-soak-summary", type=Path)
    parser.add_argument("--network-scale-soak-summary", type=Path)
    parser.add_argument("--security-drills-summary", type=Path)
    parser.add_argument("--public-beta-known-issues", type=Path, default=DEFAULT_PUBLIC_BETA_KNOWN_ISSUES)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--stable-known-limitations", type=Path, default=DEFAULT_LIMITATIONS)
    parser.add_argument("--waivers", type=Path)
    return parser

def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = args.out_dir.resolve() if args.out_dir.is_absolute() else (workspace / args.out_dir).resolve()
    multi_node = args.multi_node_beta_soak_summary or args.multi_node_soak_summary
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        generated_at=args.generated_at,
        production_beta_summary=resolve_path(workspace, args.production_beta_summary),
        go_no_go_summary=resolve_path(workspace, args.go_no_go_summary),
        release_certification_summary=resolve_path(workspace, args.release_certification_summary),
        ecosystem_matrix=resolve_path(workspace, args.ecosystem_matrix),
        app_platform_summary=resolve_path(workspace, args.app_platform_summary),
        multi_node_soak_summary=resolve_path(workspace, multi_node),
        network_scale_soak_summary=resolve_path(workspace, args.network_scale_soak_summary),
        security_drills_summary=resolve_path(workspace, args.security_drills_summary),
        public_beta_known_issues=resolve_path(workspace, args.public_beta_known_issues),
        policy=resolve_path(workspace, args.policy) or DEFAULT_POLICY,
        stable_known_limitations=resolve_path(workspace, args.stable_known_limitations) or DEFAULT_LIMITATIONS,
        waivers=resolve_path(workspace, args.waivers),
    )

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"Stable 1.0 readiness {summary['decision']}: {settings.out_dir / SUMMARY_FILE}")
    return exit_code

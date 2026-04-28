package network.crypta.platform.apphost.sandbox;

import java.io.IOException;
import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Provider registry and selector for AppHost sandbox launch planning.
 *
 * <p>The default registry supports the normal no-sandbox path, a conservative best-effort
 * restricted-process path, and reports {@code wasm-preview} as unsupported.
 *
 * <p>{@code LocalProcessAppHost} uses this type as the narrow policy-to-provider boundary. The
 * registry maps a manifest mode to one provider, asks that provider to prepare the launch, and
 * converts missing optional providers into token-free unsupported status. Missing required
 * providers become {@link AppSandboxException} failures so Platform API can return the {@code
 * unsupported_sandbox} error instead of starting the app silently.
 *
 * <p>The default composition is intentionally conservative. It does not claim container, jail,
 * seccomp, chroot, or WebAssembly isolation. Future embeddings can construct an explicit registry
 * with additional providers without changing the manifest parser or AppHost status model.
 */
public final class AppSandboxProviders {
  /** Provider used for the backward-compatible no-sandbox launch path. */
  private final AppSandboxProvider noSandboxProvider;

  /** Provider used for the v1 best-effort restricted-process launch path, when configured. */
  private final AppSandboxProvider restrictedProcessProvider;

  /** Optional provider reserved for a future WebAssembly runtime integration. */
  private final AppSandboxProvider wasmPreviewProvider;

  /**
   * Creates the default provider registry.
   *
   * <p>The default registry always includes {@link NoSandboxProvider} and {@link
   * RestrictedProcessSandboxProvider}. It deliberately leaves the WASM preview provider unset so
   * {@code sandbox.mode=wasm-preview} reports unsupported unless a future embedding wires a
   * concrete runtime.
   */
  public AppSandboxProviders() {
    this(new NoSandboxProvider(), new RestrictedProcessSandboxProvider(), null);
  }

  /**
   * Creates an explicit provider registry.
   *
   * <p>This constructor is primarily for tests and future host embeddings that need to replace or
   * add providers. The no-sandbox provider is required because {@code sandbox.mode=none} is the
   * backward-compatible manifest default. The other provider slots may be {@code null}; unsupported
   * required policies will fail at launch time, while optional policies will report unsupported
   * status and keep the original launch values.
   *
   * @param noSandboxProvider provider for {@code sandbox.mode=none}; must not be {@code null}
   * @param restrictedProcessProvider provider for {@code sandbox.mode=restricted-process}, or
   *     {@code null}
   * @param wasmPreviewProvider optional future provider for {@code sandbox.mode=wasm-preview}
   */
  public AppSandboxProviders(
      AppSandboxProvider noSandboxProvider,
      AppSandboxProvider restrictedProcessProvider,
      AppSandboxProvider wasmPreviewProvider) {
    this.noSandboxProvider = Objects.requireNonNull(noSandboxProvider, "noSandboxProvider");
    this.restrictedProcessProvider = restrictedProcessProvider;
    this.wasmPreviewProvider = wasmPreviewProvider;
  }

  /**
   * Returns a default provider registry.
   *
   * <p>This is the production factory used by AppHost when no embedding supplies an explicit
   * registry. Each call returns a fresh stateless registry.
   *
   * @return default sandbox providers for local AppHost process launches
   */
  public static AppSandboxProviders defaults() {
    return new AppSandboxProviders();
  }

  /**
   * Selects a provider and prepares a launch plan for the supplied context.
   *
   * <p>Provider selection follows the manifest mode exactly. If the selected provider exists and
   * reports support, its launch plan is returned. If no provider can support the mode, required
   * policies fail with {@link AppSandboxException}; optional policies return the original command,
   * environment, and working directory with an unsupported sandbox status. That behavior keeps
   * third-party apps usable on hosts without a requested optional provider while still making the
   * degradation visible.
   *
   * @param context sensitive AppHost launch context for one process start attempt
   * @return final provider launch plan containing process inputs and public status
   * @throws IOException when a required sandbox mode is unsupported or provider preparation fails
   */
  public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context) throws IOException {
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    AppSandboxProvider provider = providerFor(checkedContext.policy().mode());
    if (provider != null && provider.supports(checkedContext.policy())) {
      return provider.prepareLaunch(checkedContext);
    }
    AppSandboxStatus unsupported = unsupportedStatus(checkedContext.policy());
    if (checkedContext.policy().required()) {
      throw AppSandboxException.unsupportedRequired(unsupported);
    }
    return new AppSandboxLaunchPlan(
        checkedContext.command(),
        checkedContext.environment(),
        checkedContext.workingDirectory(),
        unsupported);
  }

  /**
   * Returns an inactive status for a policy using the default registry semantics.
   *
   * <p>Installed-but-stopped app summaries need to describe the requested policy before any process
   * has been launched. This helper mirrors default registry behavior without constructing a process
   * launch context or exposing launch secrets.
   *
   * @param policy requested sandbox policy from an installed manifest
   * @return token-free status safe for installed and stopped app summaries
   */
  public static AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
    return AppSandboxStatus.inactive(policy);
  }

  private AppSandboxProvider providerFor(AppSandboxMode mode) {
    return switch (mode) {
      case NONE -> noSandboxProvider;
      case RESTRICTED_PROCESS -> restrictedProcessProvider;
      case WASM_PREVIEW -> wasmPreviewProvider;
    };
  }

  private static AppSandboxStatus unsupportedStatus(AppSandboxPolicy policy) {
    String reason =
        switch (policy.mode()) {
          case RESTRICTED_PROCESS -> "restricted-process sandbox is not available on this host";
          case WASM_PREVIEW ->
              "wasm-preview sandbox is reserved for a future provider and is not available on this"
                  + " host";
          case NONE -> "no-sandbox provider is not available on this host";
        };
    return AppSandboxStatus.unsupported(policy, reason);
  }
}

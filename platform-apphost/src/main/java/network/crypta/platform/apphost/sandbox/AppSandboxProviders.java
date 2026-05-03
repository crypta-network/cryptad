package network.crypta.platform.apphost.sandbox;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Provider registry and selector for AppHost sandbox launch planning.
 *
 * <p>The default registry supports the normal no-sandbox path, prefers Linux bubblewrap for
 * restricted-process launches when available, falls back to conservative best-effort
 * restricted-process launch hygiene for optional apps, and reports {@code wasm-preview} as
 * unsupported.
 *
 * <p>{@code LocalProcessAppHost} uses this type as the narrow policy-to-provider boundary. The
 * registry maps a manifest mode to deterministic provider selection, asks the selected provider to
 * prepare the launch, and converts missing optional providers into token-free unsupported status.
 * Missing required providers become {@link AppSandboxException} failures so Platform API can return
 * the {@code unsupported_sandbox} error instead of starting the app silently.
 *
 * <p>The default composition is intentionally conservative about its public claims. Only the
 * bubblewrap provider reports {@link AppSandboxSupportLevel#ENFORCED}, and only after a launch plan
 * has been wrapped. The best-effort provider remains available as compatibility evidence without
 * claiming container, jail, seccomp, chroot, or WebAssembly isolation.
 */
public final class AppSandboxProviders {
  /** Host configuration key that controls restricted-process provider preference. */
  public static final String SANDBOX_PROVIDER_ENV = "CRYPTAD_APPHOST_SANDBOX_PROVIDER";

  /** Host configuration key that points to an explicit bubblewrap executable. */
  public static final String BWRAP_EXECUTABLE_ENV = "CRYPTAD_APPHOST_BWRAP";

  private static final String SANDBOX_PROVIDER_PROPERTY = "cryptad.apphost.sandbox.provider";
  private static final String BWRAP_EXECUTABLE_PROPERTY = "cryptad.apphost.bwrap";

  /** Provider used for the backward-compatible no-sandbox launch path. */
  private final AppSandboxProvider noSandboxProvider;

  /** Providers considered for restricted-process launch planning, in deterministic precedence. */
  private final List<AppSandboxProvider> restrictedProcessProviders;

  /**
   * Whether an unavailable restricted-process provider preference should reject optional starts.
   */
  private final boolean failRestrictedProcessWhenUnavailable;

  /** Optional provider reserved for a future WebAssembly runtime integration. */
  private final AppSandboxProvider wasmPreviewProvider;

  /**
   * Creates the default provider registry.
   *
   * <p>The default registry always includes {@link NoSandboxProvider}, attempts to select {@link
   * BubblewrapSandboxProvider} for restricted-process launches on supported Linux hosts, and keeps
   * {@link RestrictedProcessSandboxProvider} as an optional fallback. It deliberately leaves the
   * WASM preview provider unset so {@code sandbox.mode=wasm-preview} reports unsupported unless a
   * future embedding wires a concrete runtime.
   */
  public AppSandboxProviders() {
    this(new AppEnv());
  }

  /**
   * Creates the default provider registry for an explicit host environment.
   *
   * <p>The registry reads host override settings from the current process environment and system
   * properties, but uses the supplied {@link AppEnv} for OS and {@code PATH} detection.
   *
   * @param appEnv host platform detector used for bubblewrap availability
   */
  public AppSandboxProviders(AppEnv appEnv) {
    this(selectionFromSystem(Objects.requireNonNull(appEnv, "appEnv")));
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
    this(
        noSandboxProvider,
        restrictedProcessProvider == null ? List.of() : List.of(restrictedProcessProvider),
        false,
        wasmPreviewProvider);
  }

  private AppSandboxProviders(DefaultProviderSelection selection) {
    this(
        new NoSandboxProvider(),
        selection.restrictedProcessProviders(),
        selection.failRestrictedProcessWhenUnavailable(),
        null);
  }

  AppSandboxProviders(
      AppSandboxProvider noSandboxProvider,
      List<AppSandboxProvider> restrictedProcessProviders,
      boolean failRestrictedProcessWhenUnavailable,
      AppSandboxProvider wasmPreviewProvider) {
    this.noSandboxProvider = Objects.requireNonNull(noSandboxProvider, "noSandboxProvider");
    this.restrictedProcessProviders =
        List.copyOf(
            Objects.requireNonNull(restrictedProcessProviders, "restrictedProcessProviders"));
    this.failRestrictedProcessWhenUnavailable = failRestrictedProcessWhenUnavailable;
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
   * Returns a default provider registry for an explicit host environment.
   *
   * @param appEnv host platform detector used for bubblewrap availability
   * @return default sandbox providers for local AppHost process launches
   */
  public static AppSandboxProviders defaults(AppEnv appEnv) {
    return new AppSandboxProviders(appEnv);
  }

  /**
   * Returns a provider registry from explicit host configuration values.
   *
   * <p>This factory is intended for tests and controlled embeddings that need deterministic
   * provider selection without mutating the ambient process environment. It recognizes {@value
   * #SANDBOX_PROVIDER_ENV} and {@value #BWRAP_EXECUTABLE_ENV}.
   *
   * @param appEnv host platform detector used for bubblewrap availability
   * @param hostConfiguration environment-style provider configuration map
   * @return configured sandbox providers for local AppHost process launches
   */
  public static AppSandboxProviders fromHostConfiguration(
      AppEnv appEnv, Map<String, String> hostConfiguration) {
    return new AppSandboxProviders(
        selectionFromConfiguration(
            Objects.requireNonNull(appEnv, "appEnv"),
            Objects.requireNonNull(hostConfiguration, "hostConfiguration")));
  }

  /**
   * Selects a provider and prepares a launch plan for the supplied context.
   *
   * <p>Provider selection follows the manifest mode exactly. {@code restricted-process} uses a
   * deterministic provider chain so bubblewrap can win on supported Linux hosts while the
   * best-effort provider remains available for optional compatibility. Required restricted-process
   * policies fail unless the selected launch plan reports {@link AppSandboxSupportLevel#ENFORCED}.
   * Other missing required providers fail with {@link AppSandboxException}; optional policies
   * return the original command, environment, and working directory with an unsupported sandbox
   * status. That behavior keeps third-party apps usable on hosts without a requested optional
   * provider while still making the degradation visible.
   *
   * @param context sensitive AppHost launch context for one process start attempt
   * @return final provider launch plan containing process inputs and public status
   * @throws IOException when a required sandbox mode is unsupported or provider preparation fails
   */
  public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context) throws IOException {
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    if (checkedContext.policy().mode() == AppSandboxMode.RESTRICTED_PROCESS) {
      return prepareRestrictedProcessLaunch(checkedContext);
    }
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
   * Returns an inactive status for a policy using conservative policy-only semantics.
   *
   * <p>Installed-but-stopped app summaries need to describe the requested policy before any process
   * has been launched. This compatibility helper does not inspect host provider configuration;
   * callers with a configured registry should use {@link #inactiveStatusFor(AppSandboxPolicy)} so
   * forced provider settings and bubblewrap availability are reflected.
   *
   * @param policy requested sandbox policy from an installed manifest
   * @return token-free status safe for installed and stopped app summaries
   */
  public static AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
    return AppSandboxStatus.inactive(policy);
  }

  /**
   * Returns an inactive status for a policy using this registry's configured provider selection.
   *
   * <p>This method is the provider-aware counterpart to {@link #prepareLaunch}. It is used for
   * installed, stopped, and never-started summaries where AppHost must describe what the current
   * host can provide without constructing a sensitive launch context. Restricted-process status
   * follows the same deterministic provider chain as launch planning: bubblewrap can report
   * inactive enforced support when selected, forced best-effort never reports enforced, and forced
   * none or unavailable forced bubblewrap reports unsupported. Required restricted-process policies
   * report unsupported unless the selected provider is enforced.
   *
   * @param policy requested sandbox policy from an installed manifest
   * @return token-free status safe for public installed and stopped app summaries
   */
  public AppSandboxStatus inactiveStatusFor(AppSandboxPolicy policy) {
    AppSandboxPolicy checkedPolicy = Objects.requireNonNull(policy, "policy");
    if (checkedPolicy.mode() == AppSandboxMode.RESTRICTED_PROCESS) {
      return inactiveRestrictedProcessStatus(checkedPolicy);
    }
    AppSandboxProvider provider = providerFor(checkedPolicy.mode());
    if (provider != null && provider.supports(checkedPolicy)) {
      return provider.inactiveStatus(checkedPolicy);
    }
    return unsupportedStatus(checkedPolicy);
  }

  private AppSandboxLaunchPlan prepareRestrictedProcessLaunch(AppSandboxLaunchContext context)
      throws IOException {
    for (AppSandboxProvider provider : restrictedProcessProviders) {
      if (!provider.supports(context.policy())) {
        continue;
      }
      AppSandboxLaunchPlan plan = provider.prepareLaunch(context);
      if (context.policy().required()
          && plan.sandboxStatus().supportLevel() != AppSandboxSupportLevel.ENFORCED) {
        throw AppSandboxException.unsupportedRequired(requiredEnforcedStatus(context.policy()));
      }
      return plan;
    }
    AppSandboxStatus unsupported = unsupportedStatus(context.policy());
    if (context.policy().required()) {
      throw AppSandboxException.unsupportedRequired(unsupported);
    }
    if (failRestrictedProcessWhenUnavailable) {
      throw new AppSandboxException("unsupported_sandbox", unsupported.reason(), unsupported);
    }
    return new AppSandboxLaunchPlan(
        context.command(), context.environment(), context.workingDirectory(), unsupported);
  }

  private AppSandboxStatus inactiveRestrictedProcessStatus(AppSandboxPolicy policy) {
    for (AppSandboxProvider provider : restrictedProcessProviders) {
      if (!provider.supports(policy)) {
        continue;
      }
      AppSandboxStatus status = provider.inactiveStatus(policy);
      if (policy.required() && status.supportLevel() != AppSandboxSupportLevel.ENFORCED) {
        return requiredEnforcedStatus(policy);
      }
      return status;
    }
    return unsupportedStatus(policy);
  }

  private AppSandboxProvider providerFor(AppSandboxMode mode) {
    return switch (mode) {
      case NONE -> noSandboxProvider;
      case RESTRICTED_PROCESS -> null;
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

  private static AppSandboxStatus requiredEnforcedStatus(AppSandboxPolicy policy) {
    return AppSandboxStatus.unsupported(
        policy, "restricted-process sandbox requires an enforced provider on this host");
  }

  private static DefaultProviderSelection selectionFromSystem(AppEnv appEnv) {
    String providerPreference =
        configuredValue(SANDBOX_PROVIDER_ENV, SANDBOX_PROVIDER_PROPERTY, System.getenv());
    String bubblewrapExecutable =
        configuredValue(BWRAP_EXECUTABLE_ENV, BWRAP_EXECUTABLE_PROPERTY, System.getenv());
    return selectionFromValues(appEnv, providerPreference, bubblewrapExecutable);
  }

  private static DefaultProviderSelection selectionFromConfiguration(
      AppEnv appEnv, Map<String, String> hostConfiguration) {
    return selectionFromValues(
        appEnv,
        hostConfiguration.get(SANDBOX_PROVIDER_ENV),
        hostConfiguration.get(BWRAP_EXECUTABLE_ENV));
  }

  private static DefaultProviderSelection selectionFromValues(
      AppEnv appEnv, String providerPreference, String bubblewrapExecutable) {
    RestrictedProcessProviderPreference preference =
        RestrictedProcessProviderPreference.from(providerPreference);
    BubblewrapSandboxProvider bubblewrapProvider =
        new BubblewrapSandboxProvider(new BubblewrapAvailability(appEnv, bubblewrapExecutable));
    RestrictedProcessSandboxProvider bestEffortProvider = new RestrictedProcessSandboxProvider();
    ArrayList<AppSandboxProvider> providers = new ArrayList<>();
    boolean failWhenUnavailable = false;
    switch (preference) {
      case AUTO -> {
        if (bubblewrapProvider.supports(
            new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false))) {
          providers.add(bubblewrapProvider);
        }
        providers.add(bestEffortProvider);
      }
      case BUBBLEWRAP -> {
        if (bubblewrapProvider.supports(
            new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false))) {
          providers.add(bubblewrapProvider);
        }
        failWhenUnavailable = true;
      }
      case BEST_EFFORT -> providers.add(bestEffortProvider);
      case NONE -> {
        // Explicitly no restricted-process provider. Optional apps report unsupported status.
      }
    }
    return new DefaultProviderSelection(List.copyOf(providers), failWhenUnavailable);
  }

  private static String configuredValue(
      String environmentName, String propertyName, Map<String, String> environment) {
    String propertyValue = System.getProperty(propertyName);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return propertyValue;
    }
    return environment.get(environmentName);
  }

  private enum RestrictedProcessProviderPreference {
    AUTO,
    BUBBLEWRAP,
    BEST_EFFORT,
    NONE;

    private static RestrictedProcessProviderPreference from(String rawValue) {
      String normalized =
          rawValue == null ? "auto" : rawValue.trim().toLowerCase(Locale.ROOT).replace('_', '-');
      return switch (normalized) {
        case "bubblewrap" -> BUBBLEWRAP;
        case "best-effort", "besteffort" -> BEST_EFFORT;
        case "none" -> NONE;
        default -> AUTO;
      };
    }
  }

  private record DefaultProviderSelection(
      List<AppSandboxProvider> restrictedProcessProviders,
      boolean failRestrictedProcessWhenUnavailable) {
    private DefaultProviderSelection {
      restrictedProcessProviders =
          List.copyOf(
              Objects.requireNonNull(restrictedProcessProviders, "restrictedProcessProviders"));
    }
  }
}

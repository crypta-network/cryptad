package network.crypta.platform.apphost.sandbox;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Conservative v1 restricted-process provider.
 *
 * <p>This provider does not claim hard OS isolation. It verifies that AppHost is launching with the
 * existing restricted local-process hygiene: explicit installed-bundle working directory, sanitized
 * environment, and app-scoped mutable directories. The status is therefore {@link
 * AppSandboxSupportLevel#BEST_EFFORT}, not {@link AppSandboxSupportLevel#ENFORCED}.
 *
 * <p>The provider is useful as a stable contract and observability point before platform-specific
 * hardening exists. It lets manifests request {@code sandbox.mode=restricted-process}, lets AppHost
 * reject malformed launch contexts, and reports clear warnings that the launch is not a container,
 * seccomp profile, chroot, jail, or WASM runtime. Future providers can strengthen the
 * implementation without changing the manifest grammar or Platform API status shape.
 */
public final class RestrictedProcessSandboxProvider implements AppSandboxProvider {
  /**
   * Stable provider name exposed through status APIs.
   *
   * <p>The value matches the manifest mode because this provider is the default implementation of
   * {@code sandbox.mode=restricted-process}.
   */
  public static final String PROVIDER_NAME = "restricted-process";

  /**
   * Creates the stateless restricted-process provider.
   *
   * <p>The provider stores no mutable per-app state. Each launch is validated entirely from the
   * supplied {@link AppSandboxLaunchContext}, which keeps provider instances safe to reuse.
   */
  public RestrictedProcessSandboxProvider() {
    // Stateless provider; every launch is validated from its AppSandboxLaunchContext.
  }

  /**
   * Returns the stable restricted-process provider name.
   *
   * @return {@code restricted-process}, safe for public sandbox status output
   */
  @Override
  public String providerName() {
    return PROVIDER_NAME;
  }

  /**
   * Returns whether the policy requests the restricted-process mode.
   *
   * <p>This selector only checks the requested manifest mode. It does not decide whether launch
   * hygiene can be validated; that happens in {@link #prepareLaunch(AppSandboxLaunchContext)}.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return {@code true} only for {@link AppSandboxMode#RESTRICTED_PROCESS}
   */
  @Override
  public boolean supports(AppSandboxPolicy policy) {
    return Objects.requireNonNull(policy, "policy").mode() == AppSandboxMode.RESTRICTED_PROCESS;
  }

  /**
   * Returns the inactive best-effort restricted-process status.
   *
   * <p>This status is used before a process has started or after provider selection chooses the
   * compatibility restricted-process provider. It preserves the provider name and best-effort
   * warnings while keeping {@code active=false}, so UI callers do not present launch hygiene as an
   * active sandbox.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return token-free inactive best-effort status for installed and stopped summaries
   */
  @Override
  public AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
    AppSandboxPolicy checkedPolicy = Objects.requireNonNull(policy, "policy");
    if (!supports(checkedPolicy)) {
      return AppSandboxStatus.unsupported(
          checkedPolicy, "restricted-process provider cannot handle requested sandbox mode");
    }
    return bestEffortStatus(checkedPolicy, false);
  }

  /**
   * Validates the AppHost launch context and returns a best-effort restricted launch plan.
   *
   * <p>The current provider does not rewrite the command or environment. Instead, it checks the
   * launch shape that AppHost already assembled: the working directory must be the installed
   * bundle, mutable directories must be app-scoped, logs must remain under the run directory, and
   * the sanitized AppHost environment must include the app id and launch token keys. The returned
   * status reports {@link AppSandboxSupportLevel#BEST_EFFORT} and includes warnings that no hard OS
   * containment is active.
   *
   * @param context sensitive AppHost launch context for one restricted-process start attempt
   * @return launch plan preserving process inputs and reporting best-effort support
   * @throws AppSandboxException if the policy is unsupported or launch hygiene cannot be validated
   */
  @Override
  public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context)
      throws AppSandboxException {
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    if (!supports(checkedContext.policy())) {
      throw new AppSandboxException(
          "unsupported_sandbox",
          "Provider restricted-process cannot handle sandbox mode "
              + checkedContext.policy().mode().manifestValue());
    }
    validateRestrictedLaunchContext(checkedContext);
    return new AppSandboxLaunchPlan(
        checkedContext.command(),
        checkedContext.environment(),
        checkedContext.workingDirectory(),
        bestEffortStatus(checkedContext.policy(), true));
  }

  private static void validateRestrictedLaunchContext(AppSandboxLaunchContext context)
      throws AppSandboxException {
    if (!context.workingDirectory().equals(context.installDir())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch",
          "restricted-process launch requires the installed bundle as working directory");
    }
    requireAppScopedDirectory(context.appId(), context.dataDir(), "dataDir");
    requireAppScopedDirectory(context.appId(), context.cacheDir(), "cacheDir");
    requireAppScopedDirectory(context.appId(), context.runDir(), "runDir");
    if (!context.logDir().equals(context.runDir())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch", "restricted-process launch requires logs under runDir");
    }
    if (!context.environment().containsKey("CRYPTAD_APP_ID")
        || !context.environment().containsKey("CRYPTAD_APP_TOKEN")) {
      throw new AppSandboxException(
          "invalid_sandbox_launch",
          "restricted-process launch requires the sanitized AppHost environment");
    }
  }

  private static void requireAppScopedDirectory(String appId, java.nio.file.Path path, String label)
      throws AppSandboxException {
    java.nio.file.Path fileName = path.getFileName();
    if (fileName == null || !appId.equals(fileName.toString())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch", "restricted-process launch requires an app-scoped " + label);
    }
  }

  private static AppSandboxStatus bestEffortStatus(AppSandboxPolicy policy, boolean active) {
    ArrayList<String> warnings = new ArrayList<>();
    warnings.add(
        "restricted-process is best-effort in this host; it is not container, seccomp, chroot,"
            + " jail, or WASM isolation");
    if (active) {
      warnings.add("AppHost applied sanitized environment and app-scoped runtime directories");
    } else {
      warnings.add("AppHost will apply sanitized environment and app-scoped runtime directories");
    }
    return new AppSandboxStatus(
        policy.mode(),
        policy.required(),
        AppSandboxSupportLevel.BEST_EFFORT,
        PROVIDER_NAME,
        active,
        active
            ? "Best-effort restricted local process launch active"
            : "Restricted-process sandbox will use AppHost best-effort launch hygiene on start",
        List.copyOf(warnings));
  }
}

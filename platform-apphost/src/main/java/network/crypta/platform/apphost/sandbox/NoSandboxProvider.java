package network.crypta.platform.apphost.sandbox;

import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Provider for the backward-compatible AppHost local process launch path.
 *
 * <p>This provider intentionally performs no sandboxing and no command rewriting. It exists so the
 * normal local child-process launch path goes through the same provider SPI as restricted and
 * future runtime modes. That keeps AppHost launch planning observable without changing behavior for
 * existing app manifests.
 *
 * <p>The returned status uses {@link AppSandboxSupportLevel#NONE}, provider name {@code
 * no-sandbox}, and a warning that the app is running without OS sandbox isolation. UI and API
 * callers should surface that warning plainly.
 */
public final class NoSandboxProvider implements AppSandboxProvider {
  /**
   * Stable provider name exposed through status APIs.
   *
   * <p>The value is shared with {@link AppSandboxStatus#NO_SANDBOX_PROVIDER} so direct provider
   * references and status serialization use the same token.
   */
  public static final String PROVIDER_NAME = AppSandboxStatus.NO_SANDBOX_PROVIDER;

  /**
   * Creates the stateless no-sandbox provider.
   *
   * <p>Instances hold no mutable launch state and can be reused across app starts. A fresh instance
   * is still cheap and is what the default registry creates.
   */
  public NoSandboxProvider() {
    // Stateless provider; no per-instance launch state needs initialization.
  }

  /**
   * Returns the stable no-sandbox provider name.
   *
   * @return {@code no-sandbox}, safe for public sandbox status output
   */
  @Override
  public String providerName() {
    return PROVIDER_NAME;
  }

  /**
   * Returns whether the policy requests the backward-compatible no-sandbox mode.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return {@code true} only for {@link AppSandboxMode#NONE}
   */
  @Override
  public boolean supports(AppSandboxPolicy policy) {
    return Objects.requireNonNull(policy, "policy").mode() == AppSandboxMode.NONE;
  }

  /**
   * Returns the unmodified local process launch plan with no-sandbox status.
   *
   * <p>The command, environment, and working directory are copied from the context. The environment
   * may contain the launch token, so callers must continue to treat the returned plan as sensitive
   * even though the public sandbox status is token-free.
   *
   * @param context sensitive AppHost launch context for one start attempt
   * @return launch plan preserving process inputs and reporting no active sandbox isolation
   */
  @Override
  public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context) {
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    return new AppSandboxLaunchPlan(
        checkedContext.command(),
        checkedContext.environment(),
        checkedContext.workingDirectory(),
        AppSandboxStatus.noSandbox(checkedContext.policy(), false));
  }
}

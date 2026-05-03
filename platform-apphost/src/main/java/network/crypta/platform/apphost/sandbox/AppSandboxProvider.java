package network.crypta.platform.apphost.sandbox;

import java.io.IOException;

/**
 * Provider SPI that turns an AppHost launch context into a final process launch plan.
 *
 * <p>Implementations are the only place where AppHost sandbox policy becomes process-launch
 * behavior. A provider receives a sensitive {@link AppSandboxLaunchContext}, decides whether it can
 * honor the requested policy, and returns an {@link AppSandboxLaunchPlan} containing the exact
 * command, environment, working directory, and public status AppHost should use.
 *
 * <p>The SPI is deliberately small for PR-206. Providers may implement no isolation, best-effort
 * local launch hygiene, or future enforced runtimes, but they must report the actual support level
 * honestly through {@link AppSandboxStatus}. Implementations must treat context values as secrets:
 * do not log environment values, launch tokens, command details that can carry secrets, or
 * host-private paths.
 */
public interface AppSandboxProvider {
  /**
   * Returns a stable provider identifier safe for API and Shell display.
   *
   * <p>The name should be short, deterministic, and independent of local filesystem state. It is
   * exposed to operators in sandbox status, so it should describe the provider family rather than a
   * transient platform detail.
   *
   * @return provider name used in token-free public sandbox status
   */
  @SuppressWarnings("unused")
  String providerName();

  /**
   * Returns whether this provider can handle the requested policy.
   *
   * <p>This method is a cheap selector check. It should not mutate host state, inspect sensitive
   * environment values, or allocate per-launch resources. Provider registries call it before {@link
   * #prepareLaunch(AppSandboxLaunchContext)} to decide whether a policy is supported.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return {@code true} when {@link #prepareLaunch(AppSandboxLaunchContext)} may be called safely
   */
  boolean supports(AppSandboxPolicy policy);

  /**
   * Returns this provider's public status before a process is launched.
   *
   * <p>Provider registries use this status for installed-but-stopped app summaries after the
   * provider has been selected from host configuration, but before AppHost has sensitive launch
   * context such as command arguments, environment values, tokens, or private paths.
   * Implementations that can advertise a concrete support level from host probing should override
   * this method and keep {@code active=false}. Providers that cannot make a selection-time claim
   * inherit the conservative policy-only status.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return token-free inactive status safe for API and Web Shell summaries
   */
  default AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
    return AppSandboxStatus.inactive(policy);
  }

  /**
   * Prepares the final process launch plan.
   *
   * <p>The returned plan is the process-launch contract AppHost will use. Providers can leave the
   * command unchanged, rewrite environment entries, set a stricter working directory, or hand off
   * to a future runtime wrapper. They should throw {@link AppSandboxException} for policy or
   * validation failures and ordinary {@link IOException} for filesystem or process-preparation
   * failures.
   *
   * @param context sensitive AppHost launch context for one app start attempt
   * @return final launch plan containing process-builder inputs and public sandbox status
   * @throws IOException if the provider cannot safely prepare the launch plan
   */
  AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context) throws IOException;
}

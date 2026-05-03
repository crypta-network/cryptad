package network.crypta.platform.apphost.sandbox;

import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Token-free, path-free sandbox status exposed through AppHost and Platform API.
 *
 * <p>The status deliberately separates requested mode from actual support level so operator
 * surfaces can distinguish an unsandboxed app, a best-effort restricted launch, an unsupported
 * required mode, and future enforced providers without overclaiming protection.
 *
 * <p>Instances of this record are safe to serialize in app list, app detail, and runtime status
 * responses. They must not contain launch tokens, browser session tokens, command lines,
 * environment values, or host-private paths. Providers should put only short, stable, operator
 * facing explanations in {@code reason} and {@code warnings}. The status is a report of what the
 * host did or can do; it is not a policy object and should not be used to authorize app API
 * requests.
 *
 * <p>The {@code active} flag is intentionally separate from {@code supportLevel}. A stopped app can
 * have a best-effort or unsupported status based on its manifest request, while a running app uses
 * {@code active} to say whether the selected provider applied restrictions during that launch.
 *
 * @param mode requested manifest sandbox mode that AppHost parsed from the signed bundle
 * @param required whether the manifest requires support for the requested mode
 * @param supportLevel actual support level reported by provider selection or launch planning
 * @param providerName stable provider name that produced this status
 * @param active whether sandbox restrictions are active for the current process launch
 * @param reason short human-readable status reason, or {@code null} when no reason is needed
 * @param warnings token-free warnings safe for API and Web Shell display
 */
public record AppSandboxStatus(
    AppSandboxMode mode,
    boolean required,
    AppSandboxSupportLevel supportLevel,
    String providerName,
    boolean active,
    String reason,
    List<String> warnings) {
  /**
   * Provider name used for the normal no-sandbox launch path.
   *
   * <p>This value appears in public status for {@code sandbox.mode=none}. It should remain stable
   * so operators and tests can recognize the backward-compatible unsandboxed process path.
   */
  public static final String NO_SANDBOX_PROVIDER = "no-sandbox";

  /**
   * Provider name used when no provider exists for a requested mode.
   *
   * <p>This is a status placeholder, not a real launch provider. It lets app summaries and runtime
   * responses report unavailable optional modes without inventing a provider identity.
   */
  public static final String UNSUPPORTED_PROVIDER = "unsupported";

  /** Warning text used whenever AppHost reports the unsandboxed local-process path. */
  private static final String NO_SANDBOX_WARNING = "App is running without OS sandbox isolation";

  private static final String POLICY_PARAMETER = "policy";
  private static final String PROVIDER_NAME_PARAMETER = "providerName";

  /**
   * Creates a validated sandbox status.
   *
   * <p>The constructor normalizes a null mode to {@link AppSandboxMode#NONE}, trims optional reason
   * text, rejects a blank provider name, and defensively copies warning text. It does not inspect
   * warning contents for secrets; callers that create status values remain responsible for keeping
   * the public text token-free and path-free.
   *
   * @throws IllegalArgumentException if {@code providerName} is blank
   * @throws NullPointerException if {@code supportLevel}, {@code providerName}, or {@code warnings}
   *     is {@code null}
   */
  public AppSandboxStatus {
    mode = Objects.requireNonNullElse(mode, AppSandboxMode.NONE);
    Objects.requireNonNull(supportLevel, "supportLevel");
    providerName = requireProviderName(providerName);
    reason = normalizeOptional(reason);
    warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
  }

  /**
   * Returns a default status for the requested policy before a process is launched.
   *
   * <p>Installed and stopped apps still need sandbox metadata in API and Shell summaries. This
   * method reports conservative support for the policy without claiming that a process is running
   * or that restrictions are active. {@code restricted-process} reports best-effort before launch
   * because no enforced provider has been selected for a concrete launch plan; {@code wasm-preview}
   * reports unsupported because no default WASM provider exists.
   *
   * @param policy requested manifest sandbox policy from an installed app
   * @return inactive status suitable for installed-but-stopped app summaries
   */
  public static AppSandboxStatus inactive(AppSandboxPolicy policy) {
    AppSandboxPolicy normalized = Objects.requireNonNull(policy, POLICY_PARAMETER);
    return switch (normalized.mode()) {
      case NONE -> noSandbox(normalized, false);
      case RESTRICTED_PROCESS ->
          new AppSandboxStatus(
              normalized.mode(),
              normalized.required(),
              AppSandboxSupportLevel.BEST_EFFORT,
              RestrictedProcessSandboxProvider.PROVIDER_NAME,
              false,
              "Restricted-process sandbox will use AppHost best-effort launch hygiene on start",
              List.of(
                  "restricted-process is best-effort in this host; it is not container, seccomp,"
                      + " chroot, jail, or WASM isolation"));
      case WASM_PREVIEW ->
          unsupported(
              normalized,
              "wasm-preview sandbox is reserved for a future provider and is not available on this"
                  + " host");
    };
  }

  /**
   * Returns a no-sandbox status for the normal launch path.
   *
   * <p>The support level is always {@link AppSandboxSupportLevel#NONE}. The warning is included in
   * both {@code reason} and {@code warnings} so compact and detailed UI surfaces can both show that
   * the app has no OS sandbox isolation.
   *
   * @param policy requested policy associated with the app or launch
   * @param active whether sandbox restrictions are active; normally {@code false} for this status
   * @return status reporting the no-sandbox provider and no OS sandbox isolation
   */
  public static AppSandboxStatus noSandbox(AppSandboxPolicy policy, boolean active) {
    AppSandboxPolicy normalized = Objects.requireNonNull(policy, POLICY_PARAMETER);
    return new AppSandboxStatus(
        normalized.mode(),
        normalized.required(),
        AppSandboxSupportLevel.NONE,
        NO_SANDBOX_PROVIDER,
        active,
        NO_SANDBOX_WARNING,
        List.of(NO_SANDBOX_WARNING));
  }

  /**
   * Returns an unsupported status for an unavailable requested mode.
   *
   * <p>Unsupported status is used both for optional degradation and for the status object attached
   * to required-mode failures. The provider name is the stable {@link #UNSUPPORTED_PROVIDER}
   * placeholder and {@code active} is always {@code false}.
   *
   * @param policy requested policy that could not be matched to a supporting provider
   * @param reason token-free reason safe for public display
   * @return unsupported sandbox status carrying the reason as its warning text
   */
  public static AppSandboxStatus unsupported(AppSandboxPolicy policy, String reason) {
    AppSandboxPolicy normalized = Objects.requireNonNull(policy, POLICY_PARAMETER);
    return new AppSandboxStatus(
        normalized.mode(),
        normalized.required(),
        AppSandboxSupportLevel.UNSUPPORTED,
        UNSUPPORTED_PROVIDER,
        false,
        reason,
        List.of(reason));
  }

  private static String requireProviderName(String value) {
    String trimmed = Objects.requireNonNull(value, PROVIDER_NAME_PARAMETER).trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException(PROVIDER_NAME_PARAMETER + " must not be blank");
    }
    return trimmed;
  }

  private static String normalizeOptional(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}

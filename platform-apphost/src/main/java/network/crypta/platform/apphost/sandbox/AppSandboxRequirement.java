package network.crypta.platform.apphost.sandbox;

/**
 * Whether an app may run when its requested sandbox mode cannot be supported by this host.
 *
 * <p>The requirement is AppHost's typed representation of the manifest boolean {@code
 * sandbox.required}. It does not describe the requested mode itself; that lives in {@link
 * AppSandboxPolicy#mode()}. Provider selection combines both values to decide whether an
 * unsupported mode becomes a visible warning or a launch-blocking error.
 *
 * <p>This distinction keeps third-party apps portable across hosts. An optional request can ask for
 * better isolation where available without making the app unusable elsewhere. A required request is
 * appropriate only when the app author or operator has decided that running without the requested
 * sandbox mode is worse than refusing to start.
 */
public enum AppSandboxRequirement {
  /**
   * The host may warn and continue when the requested sandbox mode is unavailable.
   *
   * <p>Optional is the default for manifests that omit {@code sandbox.required}. AppHost still
   * reports the unsupported mode in status so operators can see the degraded launch, but provider
   * absence does not by itself block the process.
   */
  OPTIONAL(false),

  /**
   * The host must reject launch when the requested sandbox mode is unavailable.
   *
   * <p>Required requests turn unsupported provider selection into an {@link AppSandboxException}.
   * Platform API maps that failure to the stable {@code unsupported_sandbox} error code.
   */
  REQUIRED(true);

  /** Boolean form used by manifest parsing and compatibility call sites. */
  private final boolean required;

  AppSandboxRequirement(boolean required) {
    this.required = required;
  }

  /**
   * Returns whether launch must fail for unsupported sandbox modes.
   *
   * <p>This method intentionally mirrors the manifest boolean. It says nothing about whether a
   * provider actually enforced a sandbox for a running process; callers should inspect {@link
   * AppSandboxStatus#supportLevel()} for the runtime result.
   *
   * @return {@code true} when the manifest declared {@code sandbox.required=true}
   */
  public boolean required() {
    return required;
  }

  /**
   * Converts the manifest boolean into the typed requirement model.
   *
   * <p>The conversion is deterministic and has no validation step because boolean parsing happens
   * before AppHost builds the policy model.
   *
   * @param required manifest boolean after {@code sandbox.required} validation
   * @return matching requirement value used by provider selection
   */
  public static AppSandboxRequirement fromBoolean(boolean required) {
    return required ? REQUIRED : OPTIONAL;
  }
}

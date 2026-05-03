package network.crypta.platform.apphost.sandbox;

import java.util.Optional;
import network.crypta.platform.apphost.AppHostException;

/**
 * Launch-time sandbox policy or provider failure.
 *
 * <p>{@code AppSandboxException} is the AppHost-facing error type for sandbox selection and launch
 * planning failures. It carries a stable machine-readable code so Platform API can preserve the
 * distinction between ordinary lifecycle conflicts and sandbox-specific rejection, while still
 * returning a short message that is safe for operator-facing JSON and Web Shell surfaces.
 *
 * <p>Messages must not include launch tokens, process environment values, command lines, or
 * host-private filesystem paths. Providers should use this exception for failures that a caller can
 * classify from sandbox policy alone, such as an unsupported required mode or an invalid launch
 * plan assembled by AppHost. Unexpected process I/O failures should remain ordinary {@link
 * java.io.IOException} instances from the provider boundary.
 */
public class AppSandboxException extends AppHostException {
  /** Stable machine-readable error token carried separately from the display message. */
  private final String errorCode;

  /** Optional public sandbox status associated with the in-memory launch rejection. */
  private final transient AppSandboxStatus sandboxStatus;

  /**
   * Creates a sandbox exception with a stable API error code.
   *
   * <p>The code is consumed by Platform API error mapping and should remain stable across wording
   * changes to the human-readable message. Callers should pass messages that explain the policy
   * failure without exposing runtime secrets or local paths.
   *
   * @param errorCode machine-readable Platform API error code for this sandbox failure
   * @param message token-free failure message safe for API and Shell display
   */
  public AppSandboxException(String errorCode, String message) {
    this(errorCode, message, null);
  }

  /**
   * Creates a sandbox exception with a stable API error code and public status.
   *
   * <p>The optional status lets AppHost retain token-free failure context for runtime summaries
   * when launch is rejected before a child process starts. The status must obey the same secrecy
   * rules as ordinary {@link AppSandboxStatus} instances.
   *
   * @param errorCode machine-readable Platform API error code for this sandbox failure
   * @param message token-free failure message safe for API and Shell display
   * @param sandboxStatus optional public status associated with the failed launch
   */
  public AppSandboxException(String errorCode, String message, AppSandboxStatus sandboxStatus) {
    super(message);
    this.errorCode = errorCode;
    this.sandboxStatus = sandboxStatus;
  }

  /**
   * Returns the stable machine-readable error code.
   *
   * <p>The value is intended for JSON error envelopes and audit-style classification. It is not a
   * localized message and should not include dynamic identifiers beyond the fixed error token.
   *
   * @return API error code associated with this sandbox failure
   */
  public String errorCode() {
    return errorCode;
  }

  /**
   * Returns the public status associated with this launch rejection, when available.
   *
   * @return optional token-free sandbox status safe for AppHost runtime records
   */
  public Optional<AppSandboxStatus> sandboxStatus() {
    return Optional.ofNullable(sandboxStatus);
  }

  /**
   * Creates the standard unsupported-required sandbox failure.
   *
   * <p>This helper centralizes the message used when an app manifest declares {@code
   * sandbox.required=true} but provider selection cannot produce a supported launch plan. The
   * message includes only the manifest sandbox mode and deliberately omits provider internals,
   * process tokens, and host paths.
   *
   * @param status unsupported sandbox status produced during provider selection
   * @return checked AppHost sandbox exception using the {@code unsupported_sandbox} code
   */
  public static AppSandboxException unsupportedRequired(AppSandboxStatus status) {
    return new AppSandboxException(
        "unsupported_sandbox",
        "App requires sandbox mode "
            + status.mode().manifestValue()
            + ", but no enforced provider can support it on this host",
        status);
  }
}

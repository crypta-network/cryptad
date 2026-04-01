package network.crypta.runtime.http.security;

import java.util.Objects;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.support.HTMLNode;

/**
 * Runtime-owned bridge for rendering the shared master-password form.
 *
 * <p>The node layer uses this helper when it needs the existing password prompt HTML but should not
 * depend on HTTP adapter classes directly. The bridge accepts a runtime-owned snapshot of the
 * prompt state, converts that snapshot into the legacy adapter record, and then hands control to
 * the same renderer that already powers the administrative web UI. That keeps the architectural
 * boundary clean while preserving the established form structure, wording, and submission behavior.
 *
 * <p>This class does not interpret security policy or build markup itself. Its job is intentionally
 * narrow: validate the inputs, map fields one-for-one, and delegate rendering to the current HTTP
 * implementation.
 */
public final class PasswordFormPageRenderer {
  private static final String MASTER_PASSWORD_FORM = "masterPasswordForm";

  private PasswordFormPageRenderer() {}

  /**
   * Returns the cached security-levels form target used by the legacy HTTP renderer.
   *
   * <p>This keeps runtime-owned callers aligned with the actual route mounted by {@code
   * SecurityLevelsToadlet}. The underlying toadlet resolves and caches its path during class
   * initialization, so using this helper avoids drift if the backing system property changes later.
   *
   * @return canonical cached security-levels route used by the legacy HTTP shell.
   */
  public static String resolvedSecurityLevelsPath() {
    return network.crypta.clients.http.SecurityLevelsToadlet.resolvedPath();
  }

  /**
   * Renders the shared password form through the existing HTTP implementation.
   *
   * <p>The supplied options are treated as a detached description of the prompt state. This method
   * preserves those values exactly during conversion, so the downstream renderer sees the same
   * flags, redirect target, and security-level context it would have received from legacy call
   * sites. The provided container and content node are passed through unchanged, which keeps form
   * creation and HTML assembly behavior identical to the established toadlet path.
   *
   * @param options detached prompt state that controls which password guidance and form options are
   *     rendered for the user.
   * @param ctx container used to create the form element with the correct submission endpoint and
   *     surrounding HTTP context.
   * @param securityLevelsPath configurable submission target for the standard security-levels page
   *     flow. This value is ignored when the prompt is being rendered for the first-time wizard,
   *     which always submits to the wizard-owned endpoint.
   * @param content HTML node that receives explanatory text and the generated form structure from
   *     the delegated renderer.
   * @throws NullPointerException if any argument is {@code null}, because the underlying renderer
   *     requires all inputs to be present.
   */
  public static void generate(
      PasswordPromptOptions options,
      HttpShellContainer ctx,
      String securityLevelsPath,
      HTMLNode content) {
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(ctx, "ctx");
    Objects.requireNonNull(securityLevelsPath, "securityLevelsPath");
    Objects.requireNonNull(content, "content");

    String postTo =
        options.forFirstTimeWizard()
            ? network.crypta.clients.http.FirstTimeWizardToadlet.TOADLET_URL
            : securityLevelsPath;
    HTMLNode form = ctx.addFormChild(content, postTo, MASTER_PASSWORD_FORM);
    network.crypta.clients.http.SecurityLevelsToadlet.generatePasswordFormPage(
        new network.crypta.clients.http.PasswordFormOptions(
            options.wasWrong(),
            options.forFirstTimeWizard(),
            options.forDowngrade(),
            options.forUpgrade(),
            options.physicalSecurityLevel(),
            options.redirect()),
        form,
        content);
  }
}

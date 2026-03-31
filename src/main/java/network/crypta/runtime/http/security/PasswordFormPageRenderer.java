package network.crypta.runtime.http.security;

import java.util.Objects;
import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.clients.http.ToadletContainer;
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
  private PasswordFormPageRenderer() {}

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
   * @param content HTML node that receives explanatory text and the generated form structure from
   *     the delegated renderer.
   * @throws NullPointerException if any argument is {@code null}, because the underlying renderer
   *     requires all inputs to be present.
   */
  public static void generate(
      PasswordPromptOptions options, ToadletContainer ctx, HTMLNode content) {
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(ctx, "ctx");
    Objects.requireNonNull(content, "content");

    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(
            options.wasWrong(),
            options.forFirstTimeWizard(),
            options.forDowngrade(),
            options.forUpgrade(),
            options.physicalSecurityLevel(),
            options.redirect()),
        ctx,
        content);
  }
}

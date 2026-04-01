package network.crypta.runtime.endpoints.http.security;

import java.util.Objects;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.security.PasswordFormPageRenderer;
import network.crypta.runtime.http.security.PasswordPromptOptions;
import network.crypta.support.HTMLNode;

/**
 * Endpoint-owned default implementation of the shared password prompt renderer seam.
 *
 * <p>This renderer keeps the runtime-owned password prompt seam detached from legacy HTTP adapter
 * classes while still producing the exact markup expected by the existing administrative web UI. It
 * translates the neutral {@link PasswordPromptOptions} snapshot into the legacy {@link
 * PasswordFormOptions} record, creates the form through the active {@link HttpShellContainer}, and
 * then delegates the actual page body rendering to {@link SecurityLevelsToadlet}.
 *
 * <p>The implementation is intentionally narrow and stateless. It preserves the historical
 * submitting routing rules, keeps the established {@code masterPasswordForm} identifier, and avoids
 * embedding policy decisions in the endpoint layer. Callers are expected to supply the prompt state
 * and the surrounding HTTP shell context; this class only maps and forwards that state to the
 * legacy renderer.
 *
 * <ul>
 *   <li>First-time wizard prompts submit to {@link FirstTimeWizardToadlet#TOADLET_URL}.
 *   <li>Standard prompts submitting to the cached {@link SecurityLevelsToadlet#resolvedPath()}.
 *   <li>The generated form keeps the historical {@code masterPasswordForm} name and id.
 * </ul>
 */
public final class CorePasswordFormPageRenderer implements PasswordFormPageRenderer {
  static final String MASTER_PASSWORD_FORM = "masterPasswordForm";

  /**
   * Creates the default endpoint-backed password prompt renderer.
   *
   * <p>The renderer holds no mutable state and performs no work until {@link
   * #generate(PasswordPromptOptions, HttpShellContainer, HTMLNode)} is invoked. Reusing one
   * instance therefore preserves the current behavior without introducing request-scoped caches or
   * side effects at construction time.
   */
  public CorePasswordFormPageRenderer() {
    // Intentionally empty: this renderer is stateless and defers all work to generate(...).
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation selects the historical submitting target, creates the password form
   * through the active shell container, and passes the translated legacy options to {@link
   * SecurityLevelsToadlet}. The supplied {@code content} node remains the parent for the generated
   * explanatory text and form structure, so callers receive the same HTML tree that the legacy
   * security page path would have produced.
   */
  @Override
  public void generate(PasswordPromptOptions options, HttpShellContainer ctx, HTMLNode content) {
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(ctx, "ctx");
    Objects.requireNonNull(content, "content");

    String postTo =
        options.forFirstTimeWizard()
            ? FirstTimeWizardToadlet.TOADLET_URL
            : SecurityLevelsToadlet.resolvedPath();
    HTMLNode form = ctx.addFormChild(content, postTo, MASTER_PASSWORD_FORM);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(
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

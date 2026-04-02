package network.crypta.runtime.http.security;

import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.support.HTMLNode;

/**
 * Runtime-owned seam for rendering the shared master-password form.
 *
 * <p>Runtime and node code depend on this abstraction when they need the existing password prompt
 * HTML without importing concrete HTTP adapter helpers. Implementations remain responsible for
 * preserving the established form structure, wording, and submit-target behavior.
 */
@FunctionalInterface
public interface PasswordFormPageRenderer {

  /**
   * Renders the shared password form into the supplied content node.
   *
   * @param options detached prompt state that controls which password guidance and form options are
   *     rendered for the user
   * @param ctx container used to create the form element with the correct submission endpoint and
   *     surrounding HTTP context
   * @param content HTML node that receives explanatory text and the generated form structure
   */
  void generate(PasswordPromptOptions options, HttpShellContainer ctx, HTMLNode content);
}

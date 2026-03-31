/**
 * Runtime-owned HTTP security-page rendering seams.
 *
 * <p>This package keeps the remaining password-prompt page seams under runtime ownership. Runtime
 * code can assemble immutable prompt state with {@code PasswordPromptOptions} and call {@code
 * PasswordFormPageRenderer} when it needs the shared master-password form without importing
 * adapter-owned HTTP helper types directly. That keeps node and subsystem code on the runtime side
 * of the boundary even when the final HTML still comes from older web-admin renderers.
 *
 * <p>The package remains intentionally small. It does not define security policy, build a new form
 * markup, or replace the established administrative pages. Instead, it carries a detached prompt
 * state, validates the rendering call surface, and delegates to legacy HTTP adapter renderers when
 * those implementations remain the source of truth for markup, submission targets, and
 * operator-facing wording.
 *
 * <p>When legacy HTTP rendering remains the source of truth, these seams act as the ownership
 * boundary. Higher-level runtime code should depend on the types in this package, while
 * adapter-specific implementation details stay in the HTTP layer.
 */
package network.crypta.runtime.http.security;

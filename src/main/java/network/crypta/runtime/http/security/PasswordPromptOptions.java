package network.crypta.runtime.http.security;

/**
 * Captures the detached state needed to render the shared master-password form.
 *
 * <p>This record mirrors the legacy HTTP-layer password form options while keeping ownership in a
 * neutral runtime package. Node and runtime services can assemble one immutable snapshot, pass it
 * across the architectural boundary, and let the renderer bridge translate it into adapter-owned
 * types only at the final rendering step. That keeps the seam explicit and avoids leaking UI helper
 * classes back into core code.
 *
 * <p>Each component maps directly to one rendering decision or post-submit behavior. The record
 * does not validate combinations or interpret policy. It simply preserves the prompt state so
 * downstream rendering remains identical to the historical implementation.
 *
 * @param wasWrong whether the previous password attempt failed validation, and the next page should
 *     display the corresponding error state.
 * @param forFirstTimeWizard whether the generated form should submit to the first-time setup wizard
 *     flow instead of the standard security page.
 * @param forDowngrade whether the prompt is being shown to decrypt data during a downgrade path.
 * @param forUpgrade whether the prompt is being shown to confirm or continue an upgrade path.
 * @param physicalSecurityLevel physical threat-level name that should be persisted when the form
 *     succeeds, or {@code null} when no level change is requested.
 * @param redirect optional redirect target to use after a successful submission, or {@code null}
 *     when the default destination should be kept.
 */
public record PasswordPromptOptions(
    boolean wasWrong,
    boolean forFirstTimeWizard,
    boolean forDowngrade,
    boolean forUpgrade,
    String physicalSecurityLevel,
    String redirect) {}

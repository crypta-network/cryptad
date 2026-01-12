package network.crypta.clients.http;

/**
 * Bundles the configuration for rendering the shared master-password form.
 *
 * @param wasWrong whether the previous password attempt failed validation.
 * @param forFirstTimeWizard whether the form should post to the wizard flow.
 * @param forDowngrade whether the prompt is for decrypting during downgrade.
 * @param forUpgrade whether the prompt is for confirming an upgrade password.
 * @param physicalSecurityLevel physical threat level name to persist, or {@code null}.
 * @param redirect optional redirect target after successful submission.
 */
public record PasswordFormOptions(
    boolean wasWrong,
    boolean forFirstTimeWizard,
    boolean forDowngrade,
    boolean forUpgrade,
    String physicalSecurityLevel,
    String redirect) {}

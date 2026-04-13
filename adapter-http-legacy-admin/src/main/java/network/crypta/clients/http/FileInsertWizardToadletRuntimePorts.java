package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.SecurityLevelsPort;

/**
 * Carries the detached runtime dependency needed by the file-insert wizard.
 *
 * <p>{@link FileInsertWizardToadlet} no longer needs direct access to the live daemon core, but it
 * still has to read the current network threat level before rendering `/insertfile/`. This record
 * keeps that dependency explicit and local to the HTTP package. Callers create it during toadlet
 * wiring, usually in {@link FProxyRegistrar}, and then pass the immutable bundle into the wizard
 * constructor.
 *
 * <p>The record has one invariant: the referenced {@link SecurityLevelsPort} is always present.
 * That keeps the page logic simple because default CHK or SSK selection can rely on an available
 * detached snapshot instead of handling a missing runtime collaborator. The type is immutable and
 * thread-safe as long as the supplied port implementation is safe for concurrent reads.
 *
 * @param securityLevelsPort detached runtime view that supplies the current network threat level
 *     used when the wizard chooses its default key type
 * @param insertCompatibilityModes detached HTTP-local compatibility-mode names used by the wizard
 *     insert form
 */
record FileInsertWizardToadletRuntimePorts(
    SecurityLevelsPort securityLevelsPort, InsertCompatibilityModes insertCompatibilityModes) {
  /**
   * Creates the runtime bundle for the file-insert wizard.
   *
   * <p>The compact constructor performs only null validation. It does not capture the mutable
   * daemon state, perform I/O, or read the current threat level eagerly. That keeps construction
   * cheap and lets the caller defer all runtime reads until the wizard actually renders a page.
   *
   * @throws NullPointerException if the detached security-levels port reference is {@code null}
   */
  FileInsertWizardToadletRuntimePorts {
    Objects.requireNonNull(securityLevelsPort);
    Objects.requireNonNull(insertCompatibilityModes);
  }
}

package network.crypta.crypt;

import network.crypta.support.api.ResumeContext;

/**
 * Crypto-specific resume context for persisted encrypted state.
 *
 * <p>This extension narrows where the persistent crypto state is exposed during resume. Generic
 * persistence code such as file-backed buckets, trackers, and filename generators can continue to
 * depend on {@link ResumeContext} alone. Encrypted buckets and buffers can then explicitly require
 * the additional secret material they need. They use that material to rebuild the transient cipher
 * state after deserialization or process restart.
 *
 * <p>Typical callers receive this view only inside persistence-oriented {@code onResume(...)}
 * paths. Implementations should keep the contract small and stable: it exists to reconnect
 * encrypted persistent objects to the process-local master secret, not to widen resume code into a
 * general crypto service locator. That separation keeps support-layer APIs free of direct crypto
 * coupling while preserving the existing resume behavior for encrypted storage wrappers.
 *
 * @see ResumeContext
 */
public interface CryptoResumeContext extends ResumeContext {

  /**
   * Returns the master secret used to re-establish a persistent encrypted state.
   *
   * <p>Encrypted buckets and buffers use this secret to derive the runtime keys, nonces, and other
   * transient cryptographic material that is intentionally not serialized with persistent state.
   * Implementations may return {@code null} when persistent encryption is unavailable or disabled.
   * Callers are expected to treat that as part of their own resume contract rather than assuming
   * that a usable secret is always present.
   *
   * @return the process-local master secret for persistent encrypted state, or {@code null} when
   *     persistent encryption is not configured for the current runtime
   */
  MasterSecret getPersistentMasterSecret();
}

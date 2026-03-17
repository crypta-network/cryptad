package network.crypta.runtime.spi;

/**
 * Outcome categories for legacy master-password mutations exposed through the runtime SPI.
 *
 * <p>The legacy admin page needs only a small set of user-facing results from daemon-side password
 * operations. This enum keeps those outcomes detached from daemon exception types while leaving
 * {@link java.io.IOException} as the transport for underlying filesystem failures.
 */
public enum MasterPasswordMutationStatus {
  /** The requested operation completed successfully. */
  SUCCESS,

  /** The supplied current password did not match the existing master-keys file. */
  WRONG_PASSWORD,

  /** The requested mutation cannot proceed because a password is already configured. */
  ALREADY_SET,

  /** The master-keys file appears structurally invalid or corrupted. */
  CORRUPTED_FILE
}

package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that an I/O operation cannot proceed because there is not enough free disk space on the
 * target filesystem.
 *
 * <p>This checked exception refines {@link IOException}. Code that allocates or grows files,
 * expands on-disk data structures, or writes temporary data may throw this type to indicate that
 * the operation should be aborted until additional space is made available.
 *
 * <p>Notes
 *
 * <ul>
 *   <li>No additional state is carried by this exception; callers should include path and capacity
 *       details in their own logs or error messages at the throw site if needed.
 *   <li>The class is immutable and thread-safe.
 *   <li>Typical recovery strategies include freeing disk space and retrying the operation.
 * </ul>
 *
 * <p>Thresholds and units are decided by callers (for example, required bytes or free-space
 * reserve) and are not carried by this exception.
 */
public class InsufficientDiskSpaceException extends IOException {
  // Serialization compatibility identifier.
  @Serial private static final long serialVersionUID = 1795900904922247498L;
}

package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that an I/O operation cannot proceed because there is not enough free disk space on
 * the target filesystem.
 *
 * <p>This checked exception refines {@link IOException}. Code that allocates or grows files,
 * expands on-disk data structures, or writes temporary data may throw this type to indicate that
 * the operation should be aborted until additional space is made available.
 *
 * <p>Notes
 * <ul>
 *   <li>No additional state is carried by this exception; callers should include path and
 *       capacity details in their own logs or error messages at the throw site if needed.</li>
 *   <li>The class is immutable and thread-safe.</li>
 *   <li>Typical recovery strategies include freeing disk space and retrying the operation.</li>
 * </ul>
 *
 * <p>TODO: Document concrete thresholds/units used by callers (e.g., required bytes vs. free
 * space percentage) once standardized.
 */
public class InsufficientDiskSpaceException extends IOException {
  // Serialization compatibility identifier.
  @Serial private static final long serialVersionUID = 1795900904922247498L;
}

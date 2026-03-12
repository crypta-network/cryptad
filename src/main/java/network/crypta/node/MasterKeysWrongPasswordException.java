package network.crypta.node;

import java.io.Serial;

/**
 * Indicates that the provided password cannot decrypt the {@code master.keys} file.
 *
 * <p>This checked exception is thrown by {@link MasterKeys#read(java.io.File, java.util.Random,
 * String)} when password-based decryption succeeds but the integrity check does not match, which
 * implies the password is incorrect for the current file contents.
 *
 * <p>No sensitive information is stored in this exception. Instances are immutable and thread-safe.
 */
public class MasterKeysWrongPasswordException extends Exception {

  @Serial private static final long serialVersionUID = 5075431515279831718L;
}

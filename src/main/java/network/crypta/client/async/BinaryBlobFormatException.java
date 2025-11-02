package network.crypta.client.async;

import java.io.Serial;
import network.crypta.keys.KeyVerifyException;

/**
 * Exception indicating that a Binary Blob stream is structurally invalid or cannot be interpreted.
 *
 * <p>Readers raise this exception when the top‑level magic or overall version is unexpected, when a
 * blob advertises an unknown type in strict mode, or when size fields do not match the available
 * payload. It may also wrap a {@link KeyVerifyException} if a block record cannot be validated into
 * a proper key. This error is considered non‑recoverable for the current record sequence; callers
 * typically stop processing and surface the failure to the user or upstream component.
 *
 * <p>Use this exception to distinguish format errors from transport I/O problems ({@code
 * IOException}). It intentionally does not attempt to correct or skip corrupted data in strict
 * mode. In tolerant mode, readers may skip unrecognized blob types, but structural issues such as
 * negative or inconsistent sizes remain fatal to preserve decoder safety.
 *
 * <ul>
 *   <li>Thrown by: {@link BinaryBlob#readBinaryBlob(java.io.DataInputStream, BlockSet, boolean)}
 *   <li>Typical causes: bad magic/version, unknown type (strict), inconsistent lengths, invalid key
 *       material.
 * </ul>
 */
public class BinaryBlobFormatException extends Exception {

  /** */
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates a new exception with a detail message describing the format violation.
   *
   * <p>Use this when the error condition is self‑contained and there is no underlying cause
   * exception to attach (for example, wrong magic value or unsupported overall version). The
   * message should provide actionable context suitable for logs and end‑user diagnostics.
   *
   * @param message human‑readable description of the invalid stream condition; may be {@code null}
   *     when a generic description is sufficient for the caller.
   */
  public BinaryBlobFormatException(String message) {
    super(message);
  }

  /**
   * Creates a new exception with a message and a {@link KeyVerifyException} cause.
   *
   * <p>Use this constructor when a key block could be parsed structurally but failed cryptographic
   * or semantic validation at the key layer. The original verification exception is preserved as
   * the cause to aid debugging and programmatic inspection.
   *
   * @param message human‑readable description providing context around the failed block decoding;
   *     may be {@code null} if the cause contains sufficient detail.
   * @param e the underlying {@code KeyVerifyException} produced during key construction; must be
   *     the precise cause encountered by the reader.
   */
  public BinaryBlobFormatException(String message, KeyVerifyException e) {
    super(message, e);
  }
}

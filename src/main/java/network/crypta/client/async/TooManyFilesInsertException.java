package network.crypta.client.async;

import java.io.Serial;

/**
 * Signals that an asynchronous directory insert cannot be started because the directory contains
 * more files than the implementation permits.
 *
 * <p>This exception is raised by validation logic before any network or storage activity begins. A
 * directory insert typically generates a manifest/metadata structure listing each contained file.
 * Very large directories can cause that metadata to exceed internal bounds, allocation limits, or
 * protocol constraints. In such cases, the insert is rejected at the outset so callers can choose a
 * safer strategy—for example, splitting the directory into multiple inserts, reducing the number of
 * files, or grouping files into subdirectories to keep manifests compact.
 *
 * <p>The exception is checked to encourage explicit handling by callers coordinating user flows or
 * background jobs. Instances are immutable once created, and the type carries no mutable state.
 * Because it denotes a precondition failure, retries without changing the input normally fail in
 * the same way. Callers should therefore adjust input size or layout before retrying. This type is
 * safe to construct and use from any thread; it has no thread-affinity and performs no I/O.
 *
 * <ul>
 *   <li>Responsibility: report excessive file counts detected during insert preparation.
 *   <li>Typical use: thrown from async insert setup; caught by higher-level orchestration to
 *       present guidance or to partition work.
 *   <li>Recovery: reduce file count or split into subdirectories; then re-attempt the insert.
 * </ul>
 *
 * @see java.lang.Exception
 */
public class TooManyFilesInsertException extends Exception {
  /**
   * Serialization identifier for binary compatibility.
   *
   * <p>This constant is present to maintain a stable serialized form across versions when {@code
   * TooManyFilesInsertException} instances are transmitted or persisted. It does not affect runtime
   * behavior and may be ignored by callers that do not use Java serialization.
   *
   * @serial
   */
  @Serial private static final long serialVersionUID = -5938421512308930400L;
}

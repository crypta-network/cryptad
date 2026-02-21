package network.crypta.clients.fcp;

/**
 * Identifies how a client supplies payload bytes to Freenet Client Protocol (FCP) operations.
 *
 * <p>This enum allows filter and upload messages to describe whether their data arrives inline over
 * the control connection or by referencing an on-disk file that the node can read at leisure.
 * Callers typically parse the value from the {@code DataSource} field of a {@code
 * network.crypta.support.SimpleFieldSet} and branch into streaming or file-backed staging logic.
 * Because the enum encodes an I/O contract rather than business data, it is immutable, thread-safe,
 * and can be cached freely across connection handlers.
 *
 * <p>Large payload workflows rely on {@code DataSource} to choose between immediate validation
 * (length, MIME type, hash checks) and deferred validation performed when disk reads start. The
 * value therefore influences error reporting, temporary bucket allocation, and throttling behavior
 * without changing the higher-level semantics of the enclosing message. Selecting the correct value
 * helps operators tune latency versus disk utilization when orchestrating batches of filter probes
 * or inserts.
 *
 * <p><b>Typical responsibilities</b>
 *
 * <ul>
 *   <li>Communicate whether {@code FilterMessage} and related requests should expect streamed or
 *       file-backed content.
 *   <li>Guard parsing of source-specific fields such as {@code DataLength} or {@code Filename} so
 *       validation errors remain deterministic.
 *   <li>Document the performance profile of a request for monitoring and throttling layers.
 * </ul>
 *
 * @see #DIRECT
 * @see #DISK
 */
public enum DataSource {
  /**
   * Signals that the payload travels directly over the active FCP connection and must therefore be
   * validated, length-checked, and buffered immediately before invoking the filter or insert
   * pipeline; callers generally provide {@code DataLength} and {@code MimeType} metadata alongside
   * the message so downstream handlers can size memory buckets conservatively.
   */
  DIRECT,

  /**
   * Indicates that the payload resides on disk and will be read by the node using the provided
   * {@code Filename}; this mode favors very large files because it trades upfront parsing for lazy
   * streaming from a {@code network.crypta.support.api.Bucket}, while requiring callers to ensure
   * the path is readable for the lifetime of the request.
   */
  DISK
}

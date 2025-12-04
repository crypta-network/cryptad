/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: FormatHandler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.util.Map;

/**
 * Contract for pluggable format analyzers used by the Bitcollider pipeline to enrich submissions
 * with format-specific metadata.
 *
 * <p>Implementations are responsible for determining whether they recognize a file, ingesting bytes
 * from either an in-memory stream or a file path, and returning a map of extracted attributes. The
 * interface is deliberately minimal so handlers can be implemented in small standalone modules that
 * are discovered and managed by {@link Bitcollider}. Typical usage is:
 *
 * <ul>
 *   <li>{@link #supportsExtension(String)} is consulted to select an appropriate handler.
 *   <li>{@link #analyzeInit()}, {@link #analyzeUpdate(byte[], int)}, and {@link #analyzeFinal()}
 *       are called when the handler supports incremental, in-memory processing.
 *   <li>{@link #analyzeFile(String)} is invoked instead when a handler works directly on the file
 *       system.
 *   <li>{@link #getError()} provides a human-readable description of non-fatal problems.
 * </ul>
 *
 * <p>Handlers are not required to be thread-safe; callers should create separate instances per
 * concurrent analysis flow. Attribute maps returned by the handler should contain immutable key and
 * value strings suitable for inclusion in submission payloads, and handlers should avoid retaining
 * references to caller-owned buffers beyond the scope of each method invocation.
 */
public interface FormatHandler {

  /**
   * Indicates whether this handler can process the supplied filename extension.
   *
   * <p>Selection is performed before any file I/O, so implementations should treat the extension as
   * an advisory hint and remain resilient when the actual content does not match. Returning {@code
   * true} does not obligate the handler to succeed; errors can be reported later via {@link
   * #getError()}.
   *
   * @param ext lowercase or mixed-case extension string without a leading dot; may be {@code null}
   *     or empty, in which case handlers should normally return {@code false}.
   * @return {@code true} if this handler intends to attempt analysis for the given extension,
   *     otherwise {@code false} so other handlers may be tried.
   */
  boolean supportsExtension(String ext);

  /**
   * Reports whether the handler supports incremental, in-memory analysis through {@link
   * #analyzeInit()}, {@link #analyzeUpdate(byte[], int)}, and {@link #analyzeFinal()}.
   *
   * <p>When this returns {@code true}, the caller will stream file bytes to the handler alongside
   * other hashing logic. When {@code false}, the caller will prefer {@link #analyzeFile(String)}
   * for file-based processing.
   *
   * @return {@code true} when the handler expects to receive buffered updates; {@code false} to
   *     skip memory-based analysis.
   */
  boolean supportsMemAnalyze();

  /**
   * Indicates whether the handler can analyze a file directly from the file system via {@link
   * #analyzeFile(String)}.
   *
   * <p>Handlers that return {@code true} should be prepared to open and read the referenced file
   * path. If both memory and file analysis are supported, the caller may choose either path based
   * on configuration.
   *
   * @return {@code true} when direct file processing is supported; {@code false} when only
   *     in-memory analysis is possible.
   */
  boolean supportsFileAnalyze();

  /**
   * Prepares internal state for an upcoming series of buffered updates.
   *
   * <p>Callers invoke this exactly once before the first {@link #analyzeUpdate(byte[], int)}. The
   * method should reset any previous state so the handler can be reused for multiple files. It must
   * not perform any blocking I/O and should avoid retaining large allocations beyond what is needed
   * for streaming.
   */
  void analyzeInit();

  /**
   * Consumes a chunk of file data during incremental analysis.
   *
   * <p>This method is called repeatedly between {@link #analyzeInit()} and {@link #analyzeFinal()}.
   * Implementations should treat {@code bufLen} as the number of valid bytes starting at index 0 of
   * {@code buf}. Callers may reuse the buffer; handlers must therefore copy any data they need to
   * retain beyond the scope of the call.
   *
   * @param buf byte array containing the next block of file content; never {@code null} while
   *     invoked.
   * @param bufLen number of meaningful bytes within {@code buf}; ranges from 1 up to the array
   *     length depending on stream reads.
   */
  void analyzeUpdate(byte[] buf, int bufLen);

  /**
   * Completes incremental analysis and returns extracted attributes.
   *
   * <p>Called after the last {@link #analyzeUpdate(byte[], int)}, this method should finalize any
   * hashes or metadata aggregates and return them as a string map. The returned map should be
   * either immutable or defensively copied to avoid external mutation. Returning {@code null}
   * signals that no attributes were produced; callers may consult {@link #getError()} for
   * additional context.
   *
   * @return map of attribute keys to values, or {@code null} when nothing could be derived from the
   *     streamed content.
   */
  Map<String, String> analyzeFinal();

  /**
   * Performs a one-shot analysis of the specified file path.
   *
   * <p>This method is used when {@link #supportsFileAnalyze()} returns {@code true} or when the
   * handler does not support incremental processing. Implementations should open and read the file
   * as needed, populate metadata, and close any acquired resources before returning. They should
   * not throw unchecked exceptions for common failures such as unreadable files; instead, return
   * {@code null} and expose details via {@link #getError()}.
   *
   * @param fileName absolute or relative path to the file being analyzed; callers supply the same
   *     value they are submitting for hashing.
   * @return map of extracted attributes when successful, or {@code null} when analysis yields no
   *     data or encounters a recoverable problem.
   */
  Map<String, String> analyzeFile(String fileName);

  /**
   * Provides a human-readable description of the last recoverable problem encountered.
   *
   * <p>The message is typically populated after {@link #analyzeFile(String)} or {@link
   * #analyzeFinal()} return {@code null}. Implementations may reset the message to {@code null} on
   * successful completion so callers can distinguish fresh errors from historical ones. The
   * returned string should be suitable for user-facing logs or UI surfaces.
   *
   * @return latest non-fatal error message, or {@code null} when no error has been recorded.
   */
  String getError();
}

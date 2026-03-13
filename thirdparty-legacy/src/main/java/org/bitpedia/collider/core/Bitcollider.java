/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Bitcollider.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Coordinates hashing, metadata extraction, and submission preparation for one or more input files.
 * The class owns global flags for checksum calculation, supplies progress callbacks, and wires
 * format-specific handlers so callers can treat disparate media types uniformly.
 *
 * <p>Typical usage constructs a {@link Bitcollider} with a set of {@link FormatHandler} instances,
 * toggles checksum options, assigns an optional {@link Progress} listener, and then invokes {@link
 * #generateSubmission(List, String, boolean)}. The returned {@link Submission} holds all computed
 * attributes and can later render HTML or post data to a remote lookup service. The class does not
 * perform any network I/O itself; it merely collects data for another component to submit.
 *
 * <p>Instances are not thread-safe; callers should confine each instance to a single thread or
 * synchronize externally when sharing mutable state such as progress callbacks or warning fields.
 * Objects created through this API are long-lived only for the duration of a single submission
 * workflow; discard and recreate them if configuration or handler sets change.
 *
 * <ul>
 *   <li>Discovers files and directories and delegates per-file analysis to {@link Submission}.
 *   <li>Tracks warnings and non-fatal errors raised by handlers so a UI can surface them later.
 *   <li>Offers coarse-grained progress reporting suitable for console or GUI consumption.
 * </ul>
 *
 * @see Submission
 * @see FormatHandler
 */
public class Bitcollider {

  private static final Logger LOGGER = Logger.getLogger(Bitcollider.class.getName());

  /**
   * Human-readable agent identifier included in submission headers; remains constant at runtime.
   */
  public static final String BC_AGENTNAME = "jBitprinter";

  /* You may want to change this to a build identifier of your own, instead
  of using a timestamp */
  /** Build stamp for the agent string, typically a timestamp or CI build identifier. */
  public static final String BC_AGENTBUILD = "03/16/2006 18:15";

  /* This indicates the version of the official submission spec */
  /**
   * Version number of the Bitzi submission specification that generated submissions claim to
   * follow.
   */
  public static final String BC_SUBMITSPECVER = "0.4";

  /* Your agent-version string; should be #[.#[.#[etc]]] format */
  /** Semantic-style version identifier for this Bitcollider implementation. */
  public static final String BC_VERSION = "0.6.0";

  /**
   * Builds the canonical agent string composed of name, version, and build stamp.
   *
   * <p>The returned value is stable for the lifetime of the process and is reused in submission
   * headers so external services can attribute incoming requests to a specific implementation
   * release. Callers should avoid caching separately because the method is inexpensive and produces
   * consistent output.
   *
   * @return formatted agent string of the form {@code <name>/<version> (<build>)} for display and
   *     submission metadata.
   */
  public static String getAgentString() {
    return Bitcollider.BC_AGENTNAME
        + "/"
        + Bitcollider.BC_VERSION
        + " ("
        + Bitcollider.BC_AGENTBUILD
        + ")";
  }

  /**
   * User-facing error message set when a referenced file cannot be opened due to absence or missing
   * permissions.
   */
  public static final String ERROR_FILENOTFOUND = "File not found or permission denied.";

  /**
   * Fatal error message recorded when an internal hash implementation fails its own initialization
   * or verification checks during analysis.
   */
  public static final String ERROR_HASHCHECK =
      "The hash functions compiled into this version of the bitcollider utility are faulty!!!";

  /**
   * Warning displayed when an MP3-specific handler rejects a file after inspection and metadata
   * extraction should be skipped.
   */
  public static final String WARNING_NOTMP3 = "This is not an MP3 file. Skipping mp3 information.";

  /**
   * Progress callback used by clients to receive incremental updates during hashing and traversal.
   * Implementations should be lightweight because they are invoked from the analysis loop.
   */
  public interface Progress {

    /**
     * Reports cumulative progress for the current submission.
     *
     * @param percent integer percent complete in the range 0–100, monotonically increasing during a
     *     run.
     * @param fileName name of the file currently being analyzed, or {@code null} when unchanged
     *     since the previous callback.
     * @param message optional human-readable status text; may be {@code null} when unchanged.
     */
    void progress(int percent, String fileName, String message);
  }

  private final Collection<FormatHandler> fmtHandlers;

  private boolean calcMd5 = false;
  private boolean calcCrc32 = false;

  private Progress progress;

  private String error;
  private String warning;
  private boolean preview;
  private boolean exitNow;

  /**
   * Returns the most recent fatal error message recorded during analysis or submission preparation.
   * The value is {@code null} when no fatal condition has been detected since construction or the
   * last reset.
   *
   * <p>Callers typically consult this after a method returns {@code false} to decide whether to
   * surface the failure to users or attempt a retry. The message is mutable and not thread-safe;
   * synchronize externally if reading concurrently with an analysis thread.
   *
   * @return last fatal error message, or {@code null} when no fatal error has been set.
   */
  public String getError() {
    return error;
  }

  /**
   * Stores a fatal error message describing the last unrecoverable condition encountered.
   *
   * <p>Setter is used by collaborating components such as {@link Submission} or format handlers to
   * propagate failure details to the orchestrating caller. Passing {@code null} clears any previous
   * message so subsequent operations start in a clean state.
   *
   * @param error human-readable fatal error description to retain for later inspection; {@code
   *     null} clears the field.
   */
  public void setError(String error) {
    this.error = error;
  }

  /**
   * Indicates whether ongoing work should abort as soon as practicable.
   *
   * <p>This flag is polled inside long-running loops so callers can request cancellation from
   * another thread. The class does not implement asynchronous interruption; it relies on callers to
   * set this flag and for analysis loops to honor it cooperatively.
   *
   * @return {@code true} when processing should terminate early; {@code false} to continue.
   */
  public boolean isExitNow() {
    return exitNow;
  }

  /**
   * Requests early termination of the current analysis or clears a previous cancellation request.
   *
   * <p>Once set to {@code true}, analysis loops consult this value before each read and will return
   * control to the caller as soon as possible. Clearing the flag allows subsequent operations to
   * proceed normally but does not resume a cancelled loop.
   *
   * @param exitNow {@code true} to signal cooperative cancellation; {@code false} to reset the
   *     signal for future runs.
   */
  public void setExitNow(boolean exitNow) {
    this.exitNow = exitNow;
  }

  /**
   * Reports whether the collider is running in preview mode.
   *
   * <p>When preview is enabled, {@link Submission#analyzeFile(String, boolean)} short-circuits
   * after header preparation to estimate workload without performing hashing. Callers can use this
   * to present confirmation prompts or dry-run counts before committing to full analysis.
   *
   * @return {@code true} if preview mode is enabled and costly work should be skipped.
   */
  public boolean isPreview() {
    return preview;
  }

  /**
   * Enables or disables preview mode for subsequent analysis calls.
   *
   * <p>Setting this flag affects only future operations; it does not cancel or shorten an analysis
   * already in progress. Typical UIs toggle preview before invoking {@link
   * #generateSubmission(List, String, boolean)} to obtain basic file counts without computing
   * hashes.
   *
   * @param preview {@code true} to activate preview-only behavior; {@code false} to perform full
   *     hashing.
   */
  public void setPreview(boolean preview) {
    this.preview = preview;
  }

  /**
   * Retrieves the last non-fatal warning message produced during analysis.
   *
   * <p>Warnings are used for recoverable conditions such as unsupported metadata or optional plugin
   * failures. Consumers can display these to users while still treating the submission as valid.
   *
   * @return latest warning text, or {@code null} if no warning has been set.
   */
  public String getWarning() {
    return warning;
  }

  /**
   * Records a non-fatal warning encountered during analysis.
   *
   * <p>Setting this value does not halt processing. Passing {@code null} clears previous warnings
   * so subsequent steps can report fresh information without mixing unrelated messages.
   *
   * @param warning human-readable warning to retain for inspection; {@code null} clears existing
   *     warnings.
   */
  public void setWarning(String warning) {
    this.warning = warning;
  }

  /**
   * Creates a new {@code Bitcollider} that can orchestrate submission generation using the provided
   * format handlers.
   *
   * <p>The collection is retained as-is and consulted when resolving extensions during analysis, so
   * callers should supply handlers that survive for the lifetime of the instance. The class does
   * not copy or synchronize the collection; if it is mutable, manage concurrent changes externally.
   *
   * @param fmtHandlers ordered collection of {@link FormatHandler} instances capable of handling
   *     extensions the caller expects to encounter; must not be {@code null}.
   */
  public Bitcollider(Collection<FormatHandler> fmtHandlers) {

    this.fmtHandlers = fmtHandlers;
  }

  /**
   * Resolves a format handler capable of processing the supplied extension.
   *
   * <p>The search iterates over the configured handlers in insertion order and returns the first
   * one whose {@link FormatHandler#supportsExtension(String)} method accepts the value. The lookup
   * is case-sensitive only if handlers enforce case in their implementations; callers should
   * normalize extensions before invoking this method.
   *
   * @param ext extension string without leading dot, typically lower case; {@code null} yields
   *     {@code null}.
   * @return matching {@link FormatHandler} or {@code null} when none declares support.
   */
  public FormatHandler getFormatHandler(String ext) {

    for (FormatHandler fh : fmtHandlers) {
      if (fh.supportsExtension(ext)) {
        return fh;
      }
    }

    return null;
  }

  /**
   * Builds a {@link Submission} and populates it by analyzing the supplied files and directories.
   *
   * <p>Each path in {@code fileList} is inspected: regular files are analyzed, directories are
   * traversed shallowly, and non-existent paths raise warnings. The {@code asExt} argument
   * overrides the extension used to pick a {@link FormatHandler} when non-null. The {@code
   * autoSubmit} flag is forwarded to the resulting {@link Submission} so downstream code can decide
   * whether to perform automatic posting.
   *
   * @param fileList ordered list of absolute or relative paths to analyze; iteration order is
   *     preserved.
   * @param asExt optional extension override applied to every file, or {@code null} to derive from
   *     each path.
   * @param autoSubmit {@code true} to mark the submission for automatic posting; {@code false} to
   *     leave posting to the caller.
   * @return populated {@link Submission} containing all collected attributes and state from the
   *     performed analysis.
   */
  public Submission generateSubmission(List<String> fileList, String asExt, boolean autoSubmit) {

    Submission submission = new Submission(this, asExt, autoSubmit);

    for (String fileName : fileList) {
      File file = new File(fileName);
      if (!file.exists()) {
        LOGGER.log(Level.WARNING, "Cannot find file/dir {0}. Skipping.", fileName);
      } else if (file.isFile()) {

        submission.analyzeFile(fileName, false);
      } else if (file.isDirectory()) {

        submission.recurseDir(fileName, false, false);
      } else {
        LOGGER.log(Level.WARNING, "{0} is not a regular file. Skipping.", fileName);
      }
    }

    return submission;
  }

  /**
   * Determines whether CRC32 calculation is currently enabled.
   *
   * <p>When {@code true}, hash computation in {@link Submission} includes CRC32 and stores the
   * result as a submission attribute. Disabling it reduces processing for callers uninterested in
   * that checksum.
   *
   * @return {@code true} if CRC32 should be computed alongside other hashes.
   */
  public boolean isCalcCrc32() {
    return calcCrc32;
  }

  /**
   * Enables or disables CRC32 computation for subsequent analyses.
   *
   * <p>The flag is read by {@link Submission} during hashing; changing it mid-run has no effect on
   * an already-started analysis but influences future calls. Use this to balance completeness
   * against throughput when certain checksums are optional.
   *
   * @param calcCrc32 {@code true} to include CRC32 in hash output; {@code false} to skip it.
   */
  public void setCalcCrc32(boolean calcCrc32) {
    this.calcCrc32 = calcCrc32;
  }

  /**
   * Indicates whether MD5 calculation is active for new analyses.
   *
   * <p>When enabled, {@link Submission} will compute an MD5 digest and expose it in the generated
   * attributes. Disabling the flag can speed up processing when MD5 is not required.
   *
   * @return {@code true} if MD5 should be produced in addition to mandatory hashes.
   */
  public boolean isCalcMd5() {
    return calcMd5;
  }

  /**
   * Turns MD5 calculation on or off for subsequent submissions.
   *
   * <p>The setting is consulted during {@link Submission} hash computation. Callers can toggle it
   * to align with external compatibility requirements or to reduce CPU use in batch runs.
   *
   * @param calcMd5 {@code true} to compute MD5 hashes; {@code false} to suppress them.
   */
  public void setCalcMd5(boolean calcMd5) {
    this.calcMd5 = calcMd5;
  }

  /**
   * Returns the currently registered progress listener, if any.
   *
   * <p>The callback receives incremental updates during hashing and directory traversal. Returning
   * {@code null} signifies that no listener is active and progress events will be skipped. Callers
   * can use this to inspect configuration before scheduling long-running work.
   *
   * @return current {@link Progress} implementation or {@code null} when no listener is set.
   */
  public Progress getProgress() {
    return progress;
  }

  /**
   * Assigns a progress listener to receive callbacks during analysis.
   *
   * <p>The supplied instance is invoked synchronously from the analysis thread, so it should avoid
   * heavy work or blocking calls. Passing {@code null} disables notifications until a new listener
   * is set. The reference is stored as-is; callers manage lifecycle and thread safety of the
   * listener.
   *
   * @param progress callback to receive percent and status updates, or {@code null} to disable
   *     reporting.
   */
  public void setProgress(Progress progress) {
    this.progress = progress;
  }
}

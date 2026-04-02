package network.crypta.clients.fcp;

import java.io.*;

import java.net.MalformedURLException;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a server-to-client failure notification for a single FCP {@code ClientGet} request.
 *
 * <p>The message captures the failure mode, fatality, optional human-readable explanation, and
 * request-scoped metadata such as the original identifier and any redirect URI supplied by the
 * fetch subsystem. It is produced by the fetching side of the node and consumed by FCP clients that
 * need to surface actionable errors to callers or resume persistent queues after a restart. Typical
 * consumers serialize or transmit the {@link SimpleFieldSet} representation using {@link
 * #getFieldSet(boolean)}, or rebuild the object from persistent storage via the field-set/stream
 * constructors.
 *
 * <p>Instances are immutable after construction and may be shared safely between threads. The class
 * intentionally omits heavy diagnostics to keep transmission compact; callers can consult the
 * optional {@link #tracker} for more granular code history when present. It does not retry or
 * mutate state on its own; higher layers decide whether to requeue or abandon the request based on
 * {@link #isFatal}, expected payload hints, and redirect targets.
 *
 * <ul>
 *   <li>Conveys both machine-readable codes and user-facing descriptions.
 *   <li>Supports compact binary persistence for durable client queues.
 *   <li>Honors legacy verbosity switches so older peers can omit redundant text fields.
 * </ul>
 */
public final class GetFailedMessage extends FCPMessage implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(GetFailedMessage.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Failure category reported by the fetch pipeline; indicates protocol-level reason and code.
   * Immutable and never {@code null} after construction.
   */
  final FetchExceptionMode failureMode;

  /**
   * Optional human-readable explanation supplied by the fetcher; may be {@code null} when peers
   * prefer compact messages or the failure was self-describing via the code alone.
   */
  final String extraDescription;

  /**
   * Optional tracker retaining the ordered list of contributing failure codes for diagnostics;
   * present only when verbose parsing is enabled in the originating node.
   */
  final FailureCodeTracker tracker;

  /**
   * Indicates whether the failure is considered fatal within request orchestration; fatal errors
   * normally stop retries while non-fatal failures may be retried upstream.
   */
  final boolean isFatal;

  /**
   * Caller-provided identifier used to correlate the failure with an outstanding FCP request; must
   * be stable enough to survive persistence boundaries.
   */
  final String requestIdentifier;

  /**
   * Flag noting whether the request belonged to the global queue as opposed to a single client;
   * affects bookkeeping when relaying the failure to multiple listeners.
   */
  final boolean global;

  /**
   * Hint about the expected payload size in bytes when available; set to {@code -1} when unknown so
   * callers can detect absence without relying on nulls.
   */
  final long expectedDataLength;

  /**
   * Optional expected MIME type inferred by the fetcher; helpful for error reporting or UI display
   * when content negotiation mattered.
   */
  final String expectedMimeType;

  /**
   * Indicates whether {@link #expectedDataLength} is authoritative; guards against optimistic size
   * hints that may change once headers are fully parsed.
   */
  final boolean finalizedExpected;

  /**
   * Redirect target suggested by the fetch subsystem when the request could transparently continue
   * elsewhere; often {@code null} when no alternate location is known.
   */
  final FreenetURI redirectURI;

  // Legacy threshold callback removed.

  /**
   * Builds a failure message directly from a {@link FetchException} produced by the fetch path.
   *
   * @param e source exception providing failure details; must not be {@code null}.
   * @param identifier client-supplied opaque identifier used to correlate responses end to end.
   * @param global whether the request was tracked in the global queue, impacting broadcast scope.
   *     <p><strong>Implementation note:</strong> The constructor copies all salient fields,
   *     including size and MIME hints, so the resulting message carries enough context for
   *     downstream user interfaces to render helpful diagnostics without requerying the original
   *     exception. The {@link FailureCodeTracker} is preserved when available to allow later
   *     reconstruction of intermediate failure attempts.
   */
  public GetFailedMessage(FetchException e, String identifier, boolean global) {
    if (LOG.isDebugEnabled()) LOG.debug("Creating get failed from {} for {}", e, identifier, e);
    this.tracker = e.errorCodes;
    this.failureMode = e.mode;
    this.extraDescription = e.extraMessage;
    this.isFatal = e.isFatal();
    this.requestIdentifier = identifier;
    this.global = global;
    this.expectedDataLength = e.getExpectedSize();
    this.expectedMimeType = e.getExpectedMimeType();
    this.finalizedExpected = e.finalizedSize();
    this.redirectURI = e.newURI;
  }

  /**
   * Reconstructs a failure message from a {@link SimpleFieldSet}, typically during persistence
   * reload. The parser is intentionally tolerant so clients can survive partially corrupted buffers
   * or mismatched field verbosity.
   *
   * @param fs field set containing serialized fields; must include {@code Identifier} and {@code
   *     Code} entries.
   * @param useVerboseFields whether to trust and ingest verbose text fields or recompute from code.
   * @throws MalformedURLException if a provided {@code RedirectURI} cannot be parsed reliably.
   *     <p><strong>Implementation note:</strong> When {@code useVerboseFields} is {@code false},
   *     the constructor recalculates fatality and description text from the numeric code to avoid
   *     trusting remote text fields. This helps mixed-version peers interoperate while keeping the
   *     primary error semantics tied to the authoritative error code values.
   */
  @SuppressWarnings("unused")
  public GetFailedMessage(SimpleFieldSet fs, boolean useVerboseFields)
      throws MalformedURLException {
    requestIdentifier = fs.get("Identifier");
    if (requestIdentifier == null) throw new NullPointerException();
    failureMode = FetchExceptionMode.getByCode(Integer.parseInt(fs.get("Code")));

    if (useVerboseFields) {
      isFatal = fs.getBoolean("Fatal", false);
    } else {
      isFatal = FetchException.isFatal(failureMode);
    }

    extraDescription = fs.get("ExtraDescription");
    SimpleFieldSet trackerSubset = fs.subset("Errors");
    if (trackerSubset != null) {
      tracker = new FailureCodeTracker(true, trackerSubset);
    } else {
      tracker = null;
    }
    expectedMimeType = fs.get("ExpectedMimeType");
    finalizedExpected = fs.getBoolean("FinalizedExpected", false);
    String s = fs.get("ExpectedDataLength");
    if (s != null) {
      expectedDataLength = Long.parseLong(s);
    } else expectedDataLength = -1;
    s = fs.get("RedirectURI");
    if (s != null) this.redirectURI = new FreenetURI(s);
    else this.redirectURI = null;
    this.global = fs.getBoolean("Global", false);
  }

  /**
   * Zero-argument constructor reserved for serialization frameworks that require a default entry
   * point. Fields are initialized to benign defaults and should be overwritten during
   * deserialization.
   *
   * <p>Application code should never call this constructor directly; it exists solely to satisfy
   * tools that instantiate objects reflectively before applying field data. Leaving this instance
   * in place without subsequent population will surface {@code null} or placeholder values that do
   * not represent a real failure state.
   */
  @SuppressWarnings("unused")
  GetFailedMessage() {
    // For serialization.
    failureMode = null;
    extraDescription = null;
    tracker = null;
    isFatal = false;
    requestIdentifier = null;
    global = false;
    expectedDataLength = 0;
    expectedMimeType = null;
    finalizedExpected = false;
    redirectURI = null;
  }

  /**
   * Creates a verbose {@link SimpleFieldSet} representation suitable for transmission to external
   * FCP clients. Convenience delegate that preserves the traditional verbose behavior.
   *
   * <p>Callers that do not need compactness should prefer this helper because it includes the code
   * description and short form text, which simplify UI rendering and logging on the receiving end.
   * The returned field set is created fresh for each call and can be mutated without affecting the
   * message instance.
   *
   * @return immutable field set capturing the full message contents in verbose form.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return getFieldSet(true);
  }

  /**
   * Writes this message into a {@link SimpleFieldSet} for storage or network transmission,
   * optionally eliding derived text to save bandwidth when both endpoints share static code maps.
   *
   * <p>The caller chooses whether to emit verbose descriptions or rely solely on numeric codes so
   * older peers can reconstruct text locally. Size and MIME hints are only written when known to
   * avoid misleading defaults.
   *
   * @param verbose when {@code true}, include human-readable descriptions alongside numeric codes.
   * @return mutable field set containing the selected fields; caller owns further modification.
   */
  public SimpleFieldSet getFieldSet(boolean verbose) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("Code", failureMode.code);
    if (verbose) sfs.putSingle("CodeDescription", getFailedMessage());
    if (extraDescription != null) sfs.putSingle("ExtraDescription", extraDescription);
    if (verbose) sfs.put("Fatal", isFatal);
    if (tracker != null) {
      sfs.tput("Errors", tracker.toFieldSet(verbose));
    }
    if (verbose) sfs.putSingle("ShortCodeDescription", getShortFailedMessage());
    sfs.putSingle("Identifier", requestIdentifier);
    sfs.put("Global", global);
    if (expectedDataLength > -1) {
      sfs.put("ExpectedDataLength", expectedDataLength);
    }
    if (expectedMimeType != null) sfs.putSingle("ExpectedMetadata.ContentType", expectedMimeType);
    if (finalizedExpected) sfs.putSingle("FinalizedExpected", "true");
    if (redirectURI != null) sfs.putSingle("RedirectURI", redirectURI.toString(false, false));
    return sfs;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "GetFailed";
  }

  /**
   * Rejects attempts to send this message from client to server. The protocol defines this as a
   * server-originated notification, so any inbound appearance is treated as invalid traffic.
   *
   * @param handler active connection handler receiving the message.
   * @throws MessageInvalidException always thrown to signal misuse of the message direction.
   *     <p><strong>Implementation note:</strong> This implementation never dispatches to the node;
   *     it simply raises an exception, ensuring that servers cannot be coerced into processing
   *     client-originated failure reports that could mask real errors or confuse request
   *     bookkeeping.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "GetFailed goes from server to client not the other way around",
        requestIdentifier,
        global);
  }

  /**
   * Returns the long, human-friendly description mapped to the stored failure code. The text comes
   * from the shared {@link FetchException} catalog, ensuring consistent phrasing across components
   * and making it suitable for display or structured logging. Callers can rely on this value to be
   * stable across JVM restarts because the mapping is code-driven, not populated from peer input,
   * which reduces the surface area for inconsistent localization or tampering when working with
   * untrusted peers.
   *
   * @return non-null description string conveying the primary failure reason, independent of
   *     supplemental context.
   */
  public String getFailedMessage() {
    return FetchException.getMessage(failureMode);
  }

  /**
   * Provides the concise variant of the failure description, suitable for compact UI surfaces.
   * Short messages are typically single words or brief phrases and intentionally omit auxiliary
   * detail such as redirect hints so that dashboards and logs can align columns without wrapping.
   * Use this when screen real estate is constrained but users still need a recognizable code-linked
   * label that pairs with numeric identifiers. The returned string is immutable and safe to reuse
   * across threads or cached for repeated rendering.
   *
   * @return non-null abbreviated message tied directly to the failure code.
   */
  public String getShortFailedMessage() {
    return FetchException.getShortMessage(failureMode);
  }

  /**
   * Composes a detailed message by appending any extra description supplied at fetch time to the
   * canonical long message for the failure code. This is the most informative textual form and is
   * well-suited for user-facing dialogues or error logs that need both the standardized code and
   * contextual explanation from the failing component. Use this method when communicating with
   * humans because it preserves situational nuance—such as HTTP response strings or parser
   * specifics—that would be lost if only the static error catalog were referenced.
   *
   * @return descriptive string; equals {@link #getFailedMessage()} when no extra text exists.
   */
  public String getLongFailedMessage() {
    if (extraDescription != null) return getFailedMessage() + ": " + extraDescription;
    else return getFailedMessage();
  }

  static final int VERSION = 1;

  /**
   * Serializes a compact binary form of the message for durable client queue storage. Only the
   * fields necessary for reconstruction and user-facing detail are persisted.
   *
   * @param dos destination stream; call site is responsible for buffering and closing.
   * @throws IOException if writing to the destination stream fails at any point.
   *     <p><strong>Implementation note:</strong> The stream format is versioned so future schema
   *     changes can be detected. Optional fields are encoded with explicit presence markers to keep
   *     the reader resilient to absent values while preserving ordering for backward compatibility.
   */
  public void writeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(VERSION);
    // Do not write anything redundant.
    dos.writeInt(failureMode.code);
    writePossiblyNull(extraDescription, dos);
    dos.writeBoolean(finalizedExpected);
    writePossiblyNull(redirectURI == null ? null : redirectURI.toString(), dos);
  }

  /**
   * Rebuilds a message from its binary representation stored via {@link #writeTo(DataOutputStream)}
   * while supplying request-scoped context that is not persisted in the stream.
   *
   * @param dis source stream positioned at the start of a serialized message version record.
   * @param reqID identifier wrapper carrying queue scope and caller identifier text.
   * @param expectedSize expected payload size in bytes, or {@code -1} when unknown.
   * @param expectedType expected MIME type string, or {@code null} if not available.
   * @throws StorageFormatException if the version or encoded fields are malformed or out of range.
   * @throws IOException if the stream cannot be read reliably.
   *     <p><strong>Implementation note:</strong> Only a subset of fields is read from the stream;
   *     queue scope and identifiers are supplied out-of-band to avoid duplicating information
   *     already present in queue metadata. The constructor eagerly validates version numbers to
   *     fail fast on incompatible formats.
   */
  public GetFailedMessage(
      DataInputStream dis, RequestIdentifier reqID, long expectedSize, String expectedType)
      throws StorageFormatException, IOException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version in GetFailedMessage");
    int x = dis.readInt();
    try {
      failureMode = FetchExceptionMode.getByCode(x);
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad error code");
    }
    this.isFatal = FetchException.isFatal(failureMode);
    this.extraDescription = readPossiblyNull(dis);
    this.finalizedExpected = dis.readBoolean();
    String s = readPossiblyNull(dis);
    if (s != null) {
      try {
        redirectURI = new FreenetURI(s);
      } catch (MalformedURLException e) {
        throw new StorageFormatException("Bad redirect URI in GetFailedMessage: " + e);
      }
    } else {
      redirectURI = null;
    }
    this.global = reqID.globalQueue;
    this.requestIdentifier = reqID.identifier;
    this.tracker = null; // Don't save that level of detail.
    this.expectedDataLength = expectedSize;
    this.expectedMimeType = expectedType;
  }

  private String readPossiblyNull(DataInputStream dis) throws IOException {
    if (dis.readBoolean()) {
      return dis.readUTF();
    } else {
      return null;
    }
  }

  private void writePossiblyNull(String s, DataOutputStream dos) throws IOException {
    if (s != null) {
      dos.writeBoolean(true);
      dos.writeUTF(s);
    } else {
      dos.writeBoolean(false);
    }
  }
}

package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import java.util.Locale;
import java.util.Optional;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.RequestStarter;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;

/**
 * Base message for inserting directory hierarchies through the Freenet Client Protocol (FCP).
 *
 * <p>This abstract container centralizes the parsing and validation shared by {@link
 * ClientPutDiskDirMessage} and {@link ClientPutComplexDirMessage}. A node controller builds an
 * instance from an inbound {@link SimpleFieldSet} and hands it to {@link RequestStarter}, which
 * turns the embedded metadata into the actual insert pipeline. The message spells out the target
 * {@link FreenetURI}, retry envelope, splitfile compatibility mode, compression hints, and
 * persistence knobs expected by the storage layer so that both directory flavours remain
 * interoperable.
 *
 * <p>All fields are populated during construction and the type is effectively immutable afterward,
 * which lets callers hand references across worker threads without additional synchronization. The
 * class enforces conservative defaults—such as the immediate priority class and cache-writing
 * guardrails—so that omitted wire fields cannot accidentally degrade node health. Subclasses add
 * payload handling (disk vs. complex manifests) while reusing the contract defined here.
 *
 * <ul>
 *   <li>Validates every user-supplied numeric or binary option and reports protocol errors.
 *   <li>Exposes computed defaults through getters so monitoring code can serialize them back.
 *   <li>Coordinates cache controls, compressor descriptors, and URI post-processing.
 * </ul>
 *
 * @see ClientPutDiskDirMessage
 * @see ClientPutComplexDirMessage
 */
public abstract class ClientPutDirMessage extends BaseDataCarryingMessage {
  // Some subtypes of this (ClientPutComplexDirMessage) may carry a payload.

  /** Parsed common fields used to construct {@link ClientPutDirMessage} without throwing. */
  protected static final class ParsedCommonFields {
    final String identifier;
    final FreenetURI uri;
    final int verbosity;
    final int maxRetries;
    final boolean getCHKOnly;
    final short priorityClass;
    final Persistence persistence;
    final boolean dontCompress;
    final String clientToken;
    final boolean global;
    final String defaultName;
    final boolean earlyEncode;
    final boolean canWriteClientCache;
    final String compressorDescriptor;
    final boolean forkOnCacheable;
    final int extraInsertsSingleBlock;
    final int extraInsertsSplitfileHeaderBlock;
    final InsertContext.CompatibilityMode compatibilityMode;
    final byte[] overrideSplitfileCryptoKey;
    final boolean localRequestOnly;
    final boolean realTimeFlag;
    final String targetFilename;
    final boolean ignoreUSKDatehints;

    ParsedCommonFields(
        String identifier,
        FreenetURI uri,
        int verbosity,
        int maxRetries,
        boolean getCHKOnly,
        short priorityClass,
        Persistence persistence,
        boolean dontCompress,
        String clientToken,
        boolean global,
        String defaultName,
        boolean earlyEncode,
        boolean canWriteClientCache,
        String compressorDescriptor,
        boolean forkOnCacheable,
        int extraInsertsSingleBlock,
        int extraInsertsSplitfileHeaderBlock,
        InsertContext.CompatibilityMode compatibilityMode,
        byte[] overrideSplitfileCryptoKey,
        boolean localRequestOnly,
        boolean realTimeFlag,
        String targetFilename,
        boolean ignoreUSKDatehints) {
      this.identifier = identifier;
      this.uri = uri;
      this.verbosity = verbosity;
      this.maxRetries = maxRetries;
      this.getCHKOnly = getCHKOnly;
      this.priorityClass = priorityClass;
      this.persistence = persistence;
      this.dontCompress = dontCompress;
      this.clientToken = clientToken;
      this.global = global;
      this.defaultName = defaultName;
      this.earlyEncode = earlyEncode;
      this.canWriteClientCache = canWriteClientCache;
      this.compressorDescriptor = compressorDescriptor;
      this.forkOnCacheable = forkOnCacheable;
      this.extraInsertsSingleBlock = extraInsertsSingleBlock;
      this.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeaderBlock;
      this.compatibilityMode = compatibilityMode;
      this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
      this.localRequestOnly = localRequestOnly;
      this.realTimeFlag = realTimeFlag;
      this.targetFilename = targetFilename;
      this.ignoreUSKDatehints = ignoreUSKDatehints;
    }
  }

  final String identifier;
  final FreenetURI uri;
  final int verbosity;
  final int maxRetries;
  final boolean getCHKOnly;
  final short priorityClass;
  final Persistence persistence;
  final boolean dontCompress;
  final String clientToken;
  final boolean global;
  final String defaultName;
  final boolean earlyEncode;
  final boolean canWriteClientCache;
  final String compressorDescriptor;

  /**
   * Signals whether cacheable blocks should be forked into independent inserts while obeying the
   * node's {@link Node#FORK_ON_CACHEABLE_DEFAULT} policy. Callers read this flag to decide if a
   * cache hit should spawn separate background persistence work or remain in-band with the parent
   * request, allowing UI clients to trade extra bandwidth for faster convergence on popular data.
   */
  public final boolean forkOnCacheable;

  final int extraInsertsSingleBlock;
  final int extraInsertsSplitfileHeaderBlock;
  final InsertContext.CompatibilityMode compatibilityMode;
  final byte[] overrideSplitfileCryptoKey;
  final boolean localRequestOnly;
  final boolean realTimeFlag;
  final String targetFilename;
  final boolean ignoreUSKDatehints;

  /**
   * Creates the message from already-validated common directory put fields.
   *
   * <p>Subclasses should call {@link #parseCommonFields(SimpleFieldSet)} before invoking this
   * constructor so parse failures are reported from subclass constructors instead of this non-final
   * base class constructor.
   *
   * @param parsed parsed field group produced by {@link #parseCommonFields(SimpleFieldSet)}
   */
  protected ClientPutDirMessage(ParsedCommonFields parsed) {
    identifier = parsed.identifier;
    uri = parsed.uri;
    verbosity = parsed.verbosity;
    maxRetries = parsed.maxRetries;
    getCHKOnly = parsed.getCHKOnly;
    priorityClass = parsed.priorityClass;
    persistence = parsed.persistence;
    dontCompress = parsed.dontCompress;
    clientToken = parsed.clientToken;
    global = parsed.global;
    defaultName = parsed.defaultName;
    earlyEncode = parsed.earlyEncode;
    canWriteClientCache = parsed.canWriteClientCache;
    compressorDescriptor = parsed.compressorDescriptor;
    forkOnCacheable = parsed.forkOnCacheable;
    extraInsertsSingleBlock = parsed.extraInsertsSingleBlock;
    extraInsertsSplitfileHeaderBlock = parsed.extraInsertsSplitfileHeaderBlock;
    compatibilityMode = parsed.compatibilityMode;
    overrideSplitfileCryptoKey = parsed.overrideSplitfileCryptoKey;
    localRequestOnly = parsed.localRequestOnly;
    realTimeFlag = parsed.realTimeFlag;
    targetFilename = parsed.targetFilename;
    ignoreUSKDatehints = parsed.ignoreUSKDatehints;
  }

  /**
   * Parses and validates common directory insert fields shared by both put-dir message types.
   *
   * @param fs parsed field set received from the client
   * @return parsed common values suitable for {@link #ClientPutDirMessage(ParsedCommonFields)}
   * @throws MessageInvalidException if required or optional fields are invalid
   */
  protected static ParsedCommonFields parseCommonFields(SimpleFieldSet fs)
      throws MessageInvalidException {
    String identifier = fs.get("Identifier");
    boolean global = fs.getBoolean("Global", false);
    String defaultName = fs.get("DefaultName");
    InsertContext.CompatibilityMode compatibilityMode =
        parseCompatibilityMode(fs, identifier, global);
    byte[] overrideSplitfileCryptoKey =
        parseOverrideSplitfileCryptoKey(fs, identifier, global).orElse(null);
    boolean localRequestOnly = fs.getBoolean("LocalRequestOnly", false);
    if (identifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier", null, global);
    }
    return new ParsedCommonFields(
        identifier,
        parseUri(fs, identifier, global),
        parseOptionalInt(fs, "Verbosity", "Verbosity field", identifier, global),
        parseOptionalInt(fs, "MaxRetries", "MaxSize field", identifier, global),
        fs.getBoolean("GetCHKOnly", false),
        parsePriorityClass(fs, identifier, global),
        Persistence.parseOrThrow(fs.get("Persistence"), identifier, global),
        fs.getBoolean("DontCompress", false),
        fs.get("ClientToken"),
        global,
        defaultName,
        fs.getBoolean("EarlyEncode", false),
        fs.getBoolean("WriteToClientCache", false),
        parseCompressorDescriptor(fs, identifier, global),
        parseForkOnCacheable(fs),
        fs.getInt("ExtraInsertsSingleBlock", HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK),
        fs.getInt(
            "ExtraInsertsSplitfileHeaderBlock",
            HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER),
        compatibilityMode,
        overrideSplitfileCryptoKey,
        localRequestOnly,
        fs.getBoolean("RealTimeFlag", false),
        fs.get("TargetFilename"),
        fs.getBoolean("IgnoreUSKDatehints", false));
  }

  private static boolean parseForkOnCacheable(SimpleFieldSet fs) {
    if (fs.get("ForkOnCacheable") != null) {
      return fs.getBoolean("ForkOnCacheable", false);
    }
    return Node.FORK_ON_CACHEABLE_DEFAULT;
  }

  /**
   * Serializes the message back into a {@link SimpleFieldSet} that mirrors the original request.
   *
   * <p>The resulting structure contains the normalized URI, identifier, verbosity and retry budget,
   * and flags such as {@code GetCHKOnly} or compression preferences so downstream logging or
   * round-tripping code can faithfully represent the mutation task. Optional fields—including
   * compressor descriptors and default file names—are included only when specified to keep the wire
   * format compact. The returned field set is newly allocated on every call, so callers may mutate
   * it without affecting the message, and the method is safe to invoke from concurrent inspection
   * routines. No payload data is exposed because subclasses handle directory blobs separately.
   *
   * @return mutable field set containing the canonicalized header values ready for transmission or
   *     auditing, excluding any directory payload bytes handled by subclasses.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("URI", uri.toString());
    sfs.putSingle("Identifier", identifier);
    sfs.put("Verbosity", verbosity);
    sfs.put("MaxRetries", maxRetries);
    sfs.putSingle("ClientToken", clientToken);
    sfs.put("GetCHKOnly", getCHKOnly);
    sfs.put("PriorityClass", priorityClass);
    sfs.putSingle("Persistence", persistence.toString().toLowerCase(Locale.ROOT));
    sfs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) sfs.putSingle("Codecs", compressorDescriptor);
    sfs.put("Global", global);
    sfs.putSingle("DefaultName", defaultName);
    return sfs;
  }

  private static InsertContext.CompatibilityMode parseCompatibilityMode(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String modeValue = fs.get("CompatibilityMode");
    if (modeValue == null) {
      return InsertContext.CompatibilityMode.COMPAT_DEFAULT.intern();
    }
    try {
      return InsertContext.CompatibilityMode.valueOf(modeValue).intern();
    } catch (IllegalArgumentException _) {
      try {
        int code = Integer.parseInt(modeValue);
        return InsertContext.CompatibilityMode.byCode((short) code).intern();
      } catch (NumberFormatException _) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Invalid CompatibilityMode (not a name and not a number)",
            identifier,
            global);
      } catch (IllegalArgumentException _) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Invalid CompatibilityMode (not a valid number)",
            identifier,
            global);
      }
    }
  }

  private static Optional<byte[]> parseOverrideSplitfileCryptoKey(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String key = fs.get("OverrideSplitfileCryptoKey");
    if (key == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(HexUtil.hexToBytes(key));
    } catch (NumberFormatException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid splitfile crypto key (not hex)",
          identifier,
          global);
    } catch (IndexOutOfBoundsException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid splitfile crypto key (too short)",
          identifier,
          global);
    }
  }

  private static FreenetURI parseUri(SimpleFieldSet fs, String identifier, boolean global)
      throws MessageInvalidException {
    try {
      String uriValue = fs.get("URI");
      if (uriValue == null)
        throw new MessageInvalidException(
            ProtocolErrorMessage.MISSING_FIELD, "No URI", identifier, global);
      FreenetURI parsed = new FreenetURI(uriValue);
      String[] meta = parsed.getAllMetaStrings();
      if (meta != null && meta.length == 1 && meta[0].isEmpty()) {
        parsed = parsed.setMetaString(null);
      }
      return parsed;
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, global);
    }
  }

  private static int parseOptionalInt(
      SimpleFieldSet fs,
      String fieldName,
      String errorFieldLabel,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String value = fs.get(fieldName);
    if (value == null) {
      return 0;
    }
    try {
      return Integer.parseInt(value, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing " + errorFieldLabel + ": " + e.getMessage(),
          identifier,
          global);
    }
  }

  private static short parsePriorityClass(SimpleFieldSet fs, String identifier, boolean global)
      throws MessageInvalidException {
    String priorityString = fs.get("PriorityClass");
    if (priorityString == null) {
      return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
    }
    try {
      short parsed = Short.parseShort(priorityString);
      if (!RequestStarter.isValidPriorityClass(parsed))
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Invalid priority class "
                + parsed
                + " - range is "
                + RequestStarter.PAUSED_PRIORITY_CLASS
                + " to "
                + RequestStarter.MAXIMUM_PRIORITY_CLASS,
            identifier,
            global);
      return parsed;
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing PriorityClass field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private static String parseCompressorDescriptor(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String codecs = fs.get("Codecs");
    if (codecs == null) {
      return null;
    }
    try {
      COMPRESSOR_TYPE[] compressors = COMPRESSOR_TYPE.getCompressorsArrayNoDefault(codecs);
      if (compressors.length == 0) {
        return null;
      }
      return codecs;
    } catch (InvalidCompressionCodecException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, e.getMessage(), identifier, global);
    }
  }
}

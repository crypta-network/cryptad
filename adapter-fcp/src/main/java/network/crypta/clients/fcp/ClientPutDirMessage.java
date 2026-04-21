package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import java.util.Locale;
import java.util.Optional;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;

/**
 * Base message for inserting directory hierarchies through the Freenet Client Protocol (FCP).
 *
 * <p>This abstract container centralizes the parsing and validation shared by {@link
 * ClientPutDiskDirMessage} and {@link ClientPutComplexDirMessage}. A node controller builds an
 * instance from an inbound {@link SimpleFieldSet} and hands it to the insert pipeline. The message
 * spells out the target {@link FreenetURI}, retry envelope, splitfile compatibility mode,
 * compression hints, and persistence knobs expected by the storage layer so that both directory
 * flavors remain interoperable.
 *
 * <p>All fields are populated during construction, and the type is effectively immutable afterward,
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
    private final ClientRequestParams requestParams;
    private final FcpInsertBehaviorOptions behaviorOptions;
    private final FcpInsertTuningOptions tuningOptions;
    private final String defaultName;
    private final byte[] overrideSplitfileCryptoKey;
    private final String targetFilename;

    private ParsedCommonFields(
        ClientRequestParams requestParams,
        FcpInsertBehaviorOptions behaviorOptions,
        FcpInsertTuningOptions tuningOptions,
        String defaultName,
        byte[] overrideSplitfileCryptoKey,
        String targetFilename) {
      this.requestParams = requestParams;
      this.behaviorOptions = behaviorOptions;
      this.tuningOptions = tuningOptions;
      this.defaultName = defaultName;
      this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
      this.targetFilename = targetFilename;
    }

    private ClientRequestParams requestParams() {
      return requestParams;
    }

    private FcpInsertBehaviorOptions behaviorOptions() {
      return behaviorOptions;
    }

    private FcpInsertTuningOptions tuningOptions() {
      return tuningOptions;
    }

    private String defaultName() {
      return defaultName;
    }

    private byte[] overrideSplitfileCryptoKey() {
      return overrideSplitfileCryptoKey;
    }

    private String targetFilename() {
      return targetFilename;
    }
  }

  final String identifier;
  final FreenetURI uri;
  final int verbosity;
  final int maxRetries;
  final Integer consecutiveRnfsCountAsSuccess;
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
   * node's default cache-forking policy. Callers read this flag to decide if a cache hit should
   * spawn separate background persistence work or remain in-band with the parent request, allowing
   * UI clients to trade extra bandwidth for faster convergence on popular data.
   */
  public final boolean forkOnCacheable;

  final int extraInsertsSingleBlock;
  final int extraInsertsSplitfileHeaderBlock;
  final FcpCompatibilityMode compatibilityMode;
  final byte[] overrideSplitfileCryptoKey;
  final boolean localRequestOnly;
  final boolean realTimeFlag;
  final String targetFilename;
  final boolean ignoreUSKDatehints;

  /**
   * Creates the message from an already-validated common directory put field.
   *
   * <p>Subclasses should call {@link #parseCommonFields(SimpleFieldSet)} before invoking this
   * constructor so parse failures are reported from subclass constructors instead of this non-final
   * base class constructor.
   *
   * @param parsed parsed field group produced by {@link #parseCommonFields(SimpleFieldSet)}
   */
  protected ClientPutDirMessage(ParsedCommonFields parsed) {
    ClientRequestParams requestParams = parsed.requestParams();
    FcpInsertBehaviorOptions behaviorOptions = parsed.behaviorOptions();
    FcpInsertTuningOptions tuningOptions = parsed.tuningOptions();
    identifier = requestParams.identifier();
    uri = requestParams.uri();
    verbosity = requestParams.verbosity();
    maxRetries = behaviorOptions.maxRetries();
    consecutiveRnfsCountAsSuccess = behaviorOptions.consecutiveRnfsCountAsSuccess();
    getCHKOnly = behaviorOptions.getCHKOnly();
    priorityClass = requestParams.priorityClass();
    persistence = requestParams.persistence();
    dontCompress = behaviorOptions.dontCompress();
    clientToken = requestParams.clientToken();
    global = requestParams.global();
    defaultName = parsed.defaultName();
    earlyEncode = behaviorOptions.earlyEncode();
    canWriteClientCache = tuningOptions.canWriteClientCache();
    compressorDescriptor = tuningOptions.compressorDescriptor();
    forkOnCacheable = tuningOptions.forkOnCacheable();
    extraInsertsSingleBlock = tuningOptions.extraInsertsSingleBlock();
    extraInsertsSplitfileHeaderBlock = tuningOptions.extraInsertsSplitfileHeaderBlock();
    compatibilityMode = tuningOptions.compatibilityMode();
    overrideSplitfileCryptoKey = parsed.overrideSplitfileCryptoKey();
    localRequestOnly = behaviorOptions.localRequestOnly();
    realTimeFlag = behaviorOptions.realTimeFlag();
    targetFilename = parsed.targetFilename();
    ignoreUSKDatehints = behaviorOptions.ignoreUSKDatehints();
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
    FcpCompatibilityMode compatibilityMode = parseCompatibilityMode(fs, identifier, global);
    byte[] overrideSplitfileCryptoKey =
        parseOverrideSplitfileCryptoKey(fs, identifier, global).orElse(null);
    boolean localRequestOnly = fs.getBoolean("LocalRequestOnly", false);
    if (identifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier", null, global);
    }

    FreenetURI uri = parseUri(fs, identifier, global);
    int verbosity = parseOptionalInt(fs, "Verbosity", "Verbosity field", identifier, global);
    int maxRetries = parseOptionalInt(fs, "MaxRetries", "MaxSize field", identifier, global);
    Integer consecutiveRnfsCountAsSuccess =
        parseOptionalConsecutiveRnfsCountAsSuccess(fs, identifier, global);
    boolean getCHKOnly = fs.getBoolean("GetCHKOnly", false);
    short priorityClass = parsePriorityClass(fs, identifier, global);
    Persistence persistence = Persistence.parseOrThrow(fs.get("Persistence"), identifier, global);
    boolean dontCompress = fs.getBoolean("DontCompress", false);
    String clientToken = fs.get("ClientToken");
    boolean earlyEncode = fs.getBoolean("EarlyEncode", false);
    boolean canWriteClientCache = fs.getBoolean("WriteToClientCache", false);
    String compressorDescriptor = parseCompressorDescriptor(fs, identifier, global);
    boolean forkOnCacheable = parseForkOnCacheable(fs);
    int extraInsertsSingleBlock =
        fs.getInt("ExtraInsertsSingleBlock", FcpInsertDefaults.EXTRA_INSERTS_SINGLE_BLOCK_DEFAULT);
    int extraInsertsSplitfileHeaderBlock =
        fs.getInt(
            "ExtraInsertsSplitfileHeaderBlock",
            FcpInsertDefaults.EXTRA_INSERTS_SPLITFILE_HEADER_DEFAULT);
    boolean realTimeFlag = fs.getBoolean("RealTimeFlag", false);
    String targetFilename = fs.get("TargetFilename");
    boolean ignoreUSKDatehints = fs.getBoolean("IgnoreUSKDatehints", false);

    FcpInsertBehaviorOptions behaviorOptions =
        new FcpInsertBehaviorOptions(
            getCHKOnly,
            dontCompress,
            localRequestOnly,
            maxRetries,
            consecutiveRnfsCountAsSuccess,
            earlyEncode,
            realTimeFlag,
            ignoreUSKDatehints);
    FcpInsertTuningOptions tuningOptions =
        new FcpInsertTuningOptions(
            canWriteClientCache,
            forkOnCacheable,
            compressorDescriptor,
            extraInsertsSingleBlock,
            extraInsertsSplitfileHeaderBlock,
            compatibilityMode);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            uri,
            identifier,
            verbosity,
            priorityClass,
            persistence,
            realTimeFlag,
            clientToken,
            global);

    return new ParsedCommonFields(
        requestParams,
        behaviorOptions,
        tuningOptions,
        defaultName,
        overrideSplitfileCryptoKey,
        targetFilename);
  }

  private static boolean parseForkOnCacheable(SimpleFieldSet fs) {
    if (fs.get("ForkOnCacheable") != null) {
      return fs.getBoolean("ForkOnCacheable", false);
    }
    return FcpInsertDefaults.FORK_ON_CACHEABLE_DEFAULT;
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
    if (consecutiveRnfsCountAsSuccess != null) {
      sfs.put(ClientPutBase.FIELD_CONSECUTIVE_RNFS_COUNT_AS_SUCCESS, consecutiveRnfsCountAsSuccess);
    }
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

  private static FcpCompatibilityMode parseCompatibilityMode(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String modeValue = fs.get("CompatibilityMode");
    if (modeValue == null) {
      return FcpCompatibilityMode.COMPAT_DEFAULT.intern();
    }
    try {
      if ("COMPAT_DEFAULT".equals(modeValue)) {
        return FcpCompatibilityMode.COMPAT_DEFAULT.intern();
      }
      return FcpCompatibilityMode.valueOf(modeValue).intern();
    } catch (IllegalArgumentException _) {
      try {
        int code = Integer.parseInt(modeValue);
        return FcpCompatibilityMode.byCode((short) code).intern();
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

  private static Integer parseOptionalConsecutiveRnfsCountAsSuccess(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String value = fs.get(ClientPutBase.FIELD_CONSECUTIVE_RNFS_COUNT_AS_SUCCESS);
    if (value == null) {
      return null;
    }
    try {
      int parsed = Integer.parseInt(value, 10);
      if (parsed < 0) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            ClientPutBase.FIELD_CONSECUTIVE_RNFS_COUNT_AS_SUCCESS + " must be zero or larger",
            identifier,
            global);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing "
              + ClientPutBase.FIELD_CONSECUTIVE_RNFS_COUNT_AS_SUCCESS
              + " field: "
              + e.getMessage(),
          identifier,
          global);
    }
  }

  private static short parsePriorityClass(SimpleFieldSet fs, String identifier, boolean global)
      throws MessageInvalidException {
    String priorityString = fs.get("PriorityClass");
    if (priorityString == null) {
      return FcpPriorityClasses.IMMEDIATE_SPLITFILE;
    }
    try {
      short parsed = Short.parseShort(priorityString);
      if (!FcpPriorityClasses.isValid(parsed))
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Invalid priority class "
                + parsed
                + " - range is "
                + FcpPriorityClasses.PAUSED
                + " to "
                + FcpPriorityClasses.MAXIMUM,
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

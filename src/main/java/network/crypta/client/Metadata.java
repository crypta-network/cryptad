package network.crypta.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.BaseManifestPutter;
import network.crypta.client.async.SplitFileSegmentKeys;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.crypt.SHA256;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.support.Fields;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.CountedOutputStream;
import network.crypta.support.io.NullOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Metadata parser/writer class. */
public class Metadata implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(Metadata.class);

  @Serial private static final long serialVersionUID = 1L;
  static final long FREENET_METADATA_MAGIC = 0xf053b2842d91482bL;
  static final int MAX_SPLITFILE_PARAMS_LENGTH = 32768;

  /** Soft limit, to avoid memory DoS */
  static final int MAX_SPLITFILE_BLOCKS = 1000 * 1000;

  public static final short SPLITFILE_PARAMS_SIMPLE_SEGMENT = 0;
  public static final short SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS = 1;
  public static final short SPLITFILE_PARAMS_CROSS_SEGMENT = 2;

  // URI at which this Metadata has been/will be inserted.
  FreenetURI resolvedURI;

  // Name at which this Metadata has been/will be inside container.
  String resolvedName;

  // Actual parsed data

  // document type
  DocumentType documentType;

  public enum DocumentType {
    SIMPLE_REDIRECT((byte) 0),
    MULTI_LEVEL_METADATA((byte) 1),
    SIMPLE_MANIFEST((byte) 2),
    ARCHIVE_MANIFEST((byte) 3),
    ARCHIVE_INTERNAL_REDIRECT((byte) 4),
    ARCHIVE_METADATA_REDIRECT((byte) 5),
    SYMBOLIC_SHORTLINK((byte) 6);

    final byte code;

    DocumentType(byte code) {
      this.code = code;
    }

    static DocumentType byCode(byte b) {
      if (b < 0 || b >= values().length) throw new IllegalArgumentException();
      return values()[b];
    }
  }

  /** Holder for header-derived state used by later parsing stages. */
  private record HeaderState(boolean compressed, boolean hasTopBlocks) {}

  private void readMagicVersionAndDocType(DataInputStream dis)
      throws IOException, MetadataParseException {
    long magic = dis.readLong();
    if (magic != FREENET_METADATA_MAGIC) throw new MetadataParseException("Invalid magic " + magic);
    short version = dis.readShort();
    if (version < 0 || version > 1)
      throw new MetadataParseException("Unsupported version " + version);
    parsedVersion = version;
    try {
      documentType = DocumentType.byCode(dis.readByte());
    } catch (IllegalArgumentException e) {
      throw new MetadataParseException("Unsupported document type: " + documentType);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Document type: {}", documentType);
  }

  private HeaderState readFlagsAndHashes(DataInputStream dis)
      throws IOException, MetadataParseException {
    boolean compressed = false;
    boolean hasTopBlocks = false;
    HashResult[] h = null;
    if (haveFlags()) {
      short flags = dis.readShort();
      splitfile = (flags & FLAGS_SPLITFILE) == FLAGS_SPLITFILE;
      dbr = (flags & FLAGS_DBR) == FLAGS_DBR;
      noMIME = (flags & FLAGS_NO_MIME) == FLAGS_NO_MIME;
      compressedMIME = (flags & FLAGS_COMPRESSED_MIME) == FLAGS_COMPRESSED_MIME;
      extraMetadata = (flags & FLAGS_EXTRA_METADATA) == FLAGS_EXTRA_METADATA;
      fullKeys = (flags & FLAGS_FULL_KEYS) == FLAGS_FULL_KEYS;
      compressed = (flags & FLAGS_COMPRESSED) == FLAGS_COMPRESSED;
      if ((flags & FLAGS_HASHES) == FLAGS_HASHES) {
        if (parsedVersion == 0)
          throw new MetadataParseException("Version 0 does not support hashes");
        h = HashResult.readHashes(dis);
      }
      hasTopBlocks = (flags & FLAGS_TOP_SIZE) == FLAGS_TOP_SIZE;
      if (hasTopBlocks && parsedVersion == 0)
        throw new MetadataParseException("Version 0 does not support top block data");
      specifySplitfileKey = (flags & FLAGS_SPECIFY_SPLITFILE_KEY) == FLAGS_SPECIFY_SPLITFILE_KEY;
      if ((flags & FLAGS_HASH_THIS_LAYER) == FLAGS_HASH_THIS_LAYER) {
        hashThisLayerOnly = new byte[32];
        dis.readFully(hashThisLayerOnly);
      }
    }
    hashes = h;
    return new HeaderState(compressed, hasTopBlocks);
  }

  private record TopInfo(
      long size,
      long compressedSize,
      int blocksRequired,
      int blocksTotal,
      boolean dontCompress,
      CompatibilityMode compatMode) {}

  /** Holder for initializing final top-layer fields inside constructors. */
  private record TopLayerInit(
      long size,
      long compressedSize,
      int blocksRequired,
      int blocksTotal,
      boolean dontCompress,
      CompatibilityMode compatMode,
      short parsedVersion) {}

  private TopInfo readTopBlocksInfo(DataInputStream dis, boolean hasTopBlocks)
      throws IOException, MetadataParseException {
    if (hasTopBlocks) {
      long size = dis.readLong();
      long comp = dis.readLong();
      int req = dis.readInt();
      int tot = dis.readInt();
      boolean dont = dis.readBoolean();
      short code = dis.readShort();
      CompatibilityMode compat = parseTopCompatibility(code, size);
      return new TopInfo(size, comp, req, tot, dont, compat);
    } else {
      return new TopInfo(0, 0, 0, 0, false, InsertContext.CompatibilityMode.COMPAT_UNKNOWN);
    }
  }

  private CompatibilityMode parseTopCompatibility(short code, long topSizeValue)
      throws MetadataParseException {
    if (CompatibilityMode.hasCode(code) && code != CompatibilityMode.COMPAT_CURRENT.code) {
      CompatibilityMode compat = CompatibilityMode.byCode(code);
      if (topSizeValue != 0 && compat == CompatibilityMode.COMPAT_UNKNOWN)
        maxCompatMode = CompatibilityMode.COMPAT_1416;
      return compat;
    }
    if (CompatibilityMode.maybeFutureCode(code)) {
      LOG.warn("Content may have been inserted with a newer version of Crypta?");
      return InsertContext.CompatibilityMode.COMPAT_UNKNOWN;
    }
    throw new MetadataParseException("Bad compatibility mode " + code);
  }

  private void readArchiveTypeIfNeeded(DataInputStream dis)
      throws IOException, MetadataParseException {
    if (documentType == DocumentType.ARCHIVE_MANIFEST) {
      if (LOG.isDebugEnabled()) LOG.debug("Archive manifest");
      archiveType = ARCHIVE_TYPE.getArchiveType(dis.readShort());
      if (archiveType == null) throw new MetadataParseException("Unrecognized archive type");
    }
  }

  private void readSplitfileCryptoAndLengthIfNeeded(DataInputStream dis)
      throws IOException, MetadataParseException {
    if (!splitfile) return;
    if (parsedVersion >= 1) {
      splitfileSingleCryptoAlgorithm = dis.readByte();
      if (needsExplicitSplitfileKey()) {
        byte[] key = new byte[32];
        dis.readFully(key);
        splitfileSingleCryptoKey = key;
      } else {
        if (hashThisLayerOnly != null) splitfileSingleCryptoKey = getCryptoKey(hashThisLayerOnly);
        else splitfileSingleCryptoKey = getCryptoKey(hashes);
      }
    } else {
      splitfileSingleCryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Splitfile");
    dataLength = dis.readLong();
    if (dataLength < -1)
      throw new MetadataParseException("Invalid real content length " + dataLength);
    if (dataLength == -1 && splitfile)
      throw new MetadataParseException("Splitfile must have a real-length");
  }

  private boolean needsExplicitSplitfileKey() {
    return specifySplitfileKey
        || hashes == null
        || hashes.length == 0
        || !HashResult.contains(hashes, HashType.SHA256);
  }

  private void readCompressionFieldsIfNeeded(DataInputStream dis, boolean compressed)
      throws IOException, MetadataParseException {
    if (!compressed) return;
    compressionCodec = COMPRESSOR_TYPE.getCompressorByMetadataID(dis.readShort());
    if (compressionCodec == null)
      throw new MetadataParseException("Unrecognized splitfile compression codec");
    decompressedLength = dis.readLong();
  }

  private void readMime(DataInputStream dis) throws IOException, MetadataParseException {
    if (noMIME) {
      mimeType = null;
      if (LOG.isDebugEnabled()) LOG.debug("noMIME enabled");
      return;
    }
    if (compressedMIME) {
      readCompressedMime(dis);
    } else {
      readRawMime(dis);
    }
    if (LOG.isDebugEnabled()) LOG.debug("MIME = {}", mimeType);
  }

  private void readCompressedMime(DataInputStream dis) throws IOException, MetadataParseException {
    if (LOG.isDebugEnabled()) LOG.debug("Compressed MIME");
    short x = dis.readShort();
    compressedMIMEValue = (short) (x & 32767);
    hasCompressedMIMEParams = (x & 32768) == 32768;
    if (hasCompressedMIMEParams) {
      compressedMIMEParams = dis.readShort();
      if (compressedMIMEParams != 0) {
        throw new MetadataParseException("Unrecognized MIME params ID (not yet implemented)");
      }
    }
    mimeType = DefaultMIMETypes.byNumber(compressedMIMEValue);
  }

  private void readRawMime(DataInputStream dis) throws IOException, MetadataParseException {
    byte l = dis.readByte();
    int len = l & 0xff;
    byte[] toRead = new byte[len];
    dis.readFully(toRead);
    mimeType = new String(toRead, StandardCharsets.UTF_8);
    if (LOG.isDebugEnabled()) LOG.debug("Raw MIME");
    if (!DefaultMIMETypes.isPlausibleMIMEType(mimeType))
      throw new MetadataParseException("Does not look like a MIME type: \"" + mimeType + "\"");
  }

  private void failOnUnsupportedDBR() throws MetadataParseException {
    if (dbr) {
      throw new MetadataParseException(
          "Do not support DBRs pending decision on putting them in the key!");
    }
  }

  private void readAndDiscardExtraClientMetadata(DataInputStream dis) throws IOException {
    if (!extraMetadata) return;
    int numberOfExtraFields = (dis.readShort()) & 0xffff;
    for (int i = 0; i < numberOfExtraFields; i++) {
      short type = dis.readShort();
      int len = (dis.readByte() & 0xff);
      byte[] buf = new byte[len];
      dis.readFully(buf);
      LOG.info("Ignoring type {} extra-client-metadata field of {} bytes", type, len);
    }
    extraMetadata = false;
  }

  private void readManifestIfSimple(DataInputStream dis, long length)
      throws IOException, MetadataParseException {
    if (documentType != DocumentType.SIMPLE_MANIFEST) return;
    int manifestEntryCount = dis.readInt();
    if (manifestEntryCount < 0)
      throw new MetadataParseException("Invalid manifest entry count: " + manifestEntryCount);
    manifestEntries = new HashMap<>();
    if (LOG.isDebugEnabled()) LOG.debug("Simple manifest, {} entries", manifestEntryCount);
    for (int i = 0; i < manifestEntryCount; i++) {
      short nameLength = dis.readShort();
      byte[] buf = new byte[nameLength];
      dis.readFully(buf);
      String name = new String(buf, StandardCharsets.UTF_8).intern();
      if (LOG.isDebugEnabled()) LOG.debug("Entry {} name {}", i, name);
      short len = dis.readShort();
      if (len < 0) throw new MetadataParseException("Invalid manifest entry size: " + len);
      if (len > length)
        throw new MetadataParseException(
            "Impossibly long manifest entry: " + len + " - metadata size " + length);
      byte[] data = new byte[len];
      dis.readFully(data);
      Metadata m = Metadata.construct(data);
      manifestEntries.put(name, m);
    }
    if (LOG.isDebugEnabled()) LOG.debug("End of manifest");
  }

  private void readArchiveInternalOrShortlinkIfNeeded(DataInputStream dis)
      throws IOException, MetadataParseException {
    if ((documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        || (documentType == DocumentType.ARCHIVE_METADATA_REDIRECT)
        || (documentType == DocumentType.SYMBOLIC_SHORTLINK)) {
      int len = dis.readShort();
      if (LOG.isDebugEnabled()) LOG.debug("Reading archive internal redirect length {}", len);
      byte[] buf = new byte[len];
      dis.readFully(buf);
      targetName = new String(buf, StandardCharsets.UTF_8);
      while (true) {
        if (targetName.isEmpty())
          throw new MetadataParseException(
              "Invalid target name is empty: \"" + new String(buf, StandardCharsets.UTF_8) + "\"");
        if (targetName.charAt(0) == '/') {
          targetName = targetName.substring(1);
        } else break;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Archive and/or internal redirect: {} ({})", targetName, len);
    }
  }

  private void readSimpleRedirectOrArchiveKeyIfNeeded(DataInputStream dis) throws IOException {
    if ((!splitfile)
        && ((documentType == DocumentType.SIMPLE_REDIRECT)
            || (documentType == DocumentType.ARCHIVE_MANIFEST))) {
      simpleRedirectKey = readKey(dis);
      if (simpleRedirectKey.isCHK()) {
        byte algo = ClientCHK.getCryptoAlgorithmFromExtra(simpleRedirectKey.getExtra());
        if (algo == Key.ALGO_AES_CTR_256_SHA256) {
          minCompatMode = CompatibilityMode.COMPAT_1416;
          maxCompatMode = CompatibilityMode.latest();
        } else {
          if (getParsedVersion() == 0) {
            minCompatMode = CompatibilityMode.COMPAT_1250_EXACT;
            maxCompatMode = CompatibilityMode.COMPAT_1251;
          } else {
            minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_1255;
          }
        }
      }
    }
  }

  // Splitfile parsing helpers (extracted from constructor to lower cognitive complexity)
  private void parseSplitfileHeaderAndLayout(DataInputStream dis)
      throws IOException, MetadataParseException {
    readAndValidateSplitfileAlgorithm(dis);
    readSplitfileParams(dis);
    readSplitfileBlockCounts(dis);

    if (splitfileAlgorithm == SplitfileAlgorithm.ONION_STANDARD) {
      byte[] params = splitfileParams();
      computeOnionStandardLayout(params);
      enforceTopCompatibilityOrThrow();
      apply1135WorkaroundAndFinalize();
    } else {
      throw new MetadataParseException("Unknown splitfile algorithm " + splitfileAlgorithm);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Simple {} {}", splitfileAlgorithm, segmentCount);
  }

  private void readAndValidateSplitfileAlgorithm(DataInputStream dis)
      throws IOException, MetadataParseException {
    try {
      splitfileAlgorithm = SplitfileAlgorithm.getByCode(dis.readShort());
    } catch (IllegalArgumentException e) {
      throw new MetadataParseException("Invalid splitfile code");
    }
    if (!((splitfileAlgorithm == SplitfileAlgorithm.NONREDUNDANT)
        || (splitfileAlgorithm == SplitfileAlgorithm.ONION_STANDARD)))
      throw new MetadataParseException("Unknown splitfile algorithm " + splitfileAlgorithm);

    if (splitfileAlgorithm == SplitfileAlgorithm.NONREDUNDANT)
      throw new MetadataParseException("Non-redundant splitfile invalid");
  }

  private void readSplitfileParams(DataInputStream dis) throws IOException, MetadataParseException {
    int paramsLength = dis.readInt();
    if (paramsLength > MAX_SPLITFILE_PARAMS_LENGTH)
      throw new MetadataParseException("Too many bytes of splitfile parameters: " + paramsLength);

    if (paramsLength > 0) {
      splitfileParams = new byte[paramsLength];
      dis.readFully(splitfileParams);
    } else if (paramsLength < 0) {
      throw new MetadataParseException("Invalid splitfile params length: " + paramsLength);
    }
  }

  private void readSplitfileBlockCounts(DataInputStream dis)
      throws IOException, MetadataParseException {
    splitfileBlocks = dis.readInt(); // 64TB file size limit :)
    if (splitfileBlocks < 0)
      throw new MetadataParseException("Invalid number of blocks: " + splitfileBlocks);
    if (splitfileBlocks > MAX_SPLITFILE_BLOCKS)
      throw new MetadataParseException(
          "Too many splitfile blocks (soft limit to prevent memory DoS): " + splitfileBlocks);
    splitfileCheckBlocks = dis.readInt();
    if (splitfileCheckBlocks < 0)
      throw new MetadataParseException("Invalid number of check blocks: " + splitfileCheckBlocks);
    if (splitfileCheckBlocks > MAX_SPLITFILE_BLOCKS)
      throw new MetadataParseException(
          "Too many splitfile check-blocks (soft limit to prevent memory DoS): "
              + splitfileCheckBlocks);

    crossCheckBlocks = 0;
  }

  private void computeOnionStandardLayout(byte[] params) throws MetadataParseException {
    int checkBlocks;
    if (getParsedVersion() == 0) {
      checkBlocks = computeOnionLayoutV0(params);
    } else {
      checkBlocks = computeOnionLayoutV1(params);
    }
    // Stage the computed per-segment check block count for finalization.
    checkBlocksPerSegment = checkBlocks;
  }

  private int computeOnionLayoutV0(byte[] params) throws MetadataParseException {
    if ((params == null) || (params.length < 8))
      throw new MetadataParseException("No splitfile params");
    blocksPerSegment = Fields.bytesToInt(params, 0);
    int checkBlocks = Fields.bytesToInt(params, 4);
    deductBlocksFromSegments = 0;
    int countDataBlocks = splitfileBlocks;
    int countCheckBlocks = splitfileCheckBlocks;
    if (countDataBlocks == countCheckBlocks) {
      if (blocksPerSegment == 128) {
        int segs = (countDataBlocks + 127) / 128;
        int segSize = (countDataBlocks + segs - 1) / segs;
        if (segSize == 128) {
          minCompatMode = CompatibilityMode.COMPAT_1250_EXACT;
          maxCompatMode = CompatibilityMode.COMPAT_1250;
        } else {
          minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_1250_EXACT;
        }
      } else {
        minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_1250;
      }
    } else {
      if (checkBlocks == 64) {
        minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_UNKNOWN;
      } else {
        minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_1251;
      }
    }
    return checkBlocks;
  }

  private int computeOnionLayoutV1(byte[] params) throws MetadataParseException {
    if (splitfileSingleCryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256)
      minCompatMode = maxCompatMode = CompatibilityMode.COMPAT_1255;
    else if (splitfileSingleCryptoAlgorithm == Key.ALGO_AES_CTR_256_SHA256) {
      minCompatMode = CompatibilityMode.COMPAT_1416;
      if (maxCompatMode == CompatibilityMode.COMPAT_UNKNOWN)
        maxCompatMode = CompatibilityMode.latest();
    }
    if (params.length < 10)
      throw new MetadataParseException("Splitfile parameters too short for version 1");
    short paramsType = Fields.bytesToShort(params, 0);
    int checkBlocks;
    if (paramsType == Metadata.SPLITFILE_PARAMS_SIMPLE_SEGMENT
        || paramsType == Metadata.SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS
        || paramsType == Metadata.SPLITFILE_PARAMS_CROSS_SEGMENT) {
      blocksPerSegment = Fields.bytesToInt(params, 2);
      checkBlocks = Fields.bytesToInt(params, 6);
    } else throw new MetadataParseException("Unknown splitfile params type " + paramsType);
    if (paramsType == Metadata.SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS
        || paramsType == Metadata.SPLITFILE_PARAMS_CROSS_SEGMENT) {
      deductBlocksFromSegments = Fields.bytesToInt(params, 10);
      if (paramsType == Metadata.SPLITFILE_PARAMS_CROSS_SEGMENT) {
        crossCheckBlocks = Fields.bytesToInt(params, 14);
      }
    } else deductBlocksFromSegments = 0;
    return checkBlocks;
  }

  private void enforceTopCompatibilityOrThrow() throws MetadataParseException {
    if (topCompatibilityMode != CompatibilityMode.COMPAT_UNKNOWN) {
      if (minCompatMode == CompatibilityMode.COMPAT_UNKNOWN
          || !(minCompatMode.ordinal() > topCompatibilityMode.ordinal()
              || maxCompatMode.ordinal() < topCompatibilityMode.ordinal())) {
        minCompatMode = maxCompatMode = topCompatibilityMode;
      } else
        throw new MetadataParseException(
            "Top compatibility mode is incompatible with detected compatibility mode: min="
                + minCompatMode
                + " max="
                + maxCompatMode
                + " top="
                + topCompatibilityMode);
    }
  }

  private void apply1135WorkaroundAndFinalize() {
    if (checkBlocksPerSegment == 64
        && blocksPerSegment == 128
        && splitfileCheckBlocks == splitfileBlocks - (splitfileBlocks / 128)) {
      LOG.info("Activating 1135 wrong check blocks per segment workaround for {}", this);
      checkBlocksPerSegment = 127;
    }
    segmentCount =
        (splitfileBlocks + blocksPerSegment + crossCheckBlocks - 1)
            / (blocksPerSegment + crossCheckBlocks);
  }

  // Removed unused method readSplitfileKeysAndSegmentsFromStream(DataInputStream)

  short parsedVersion;

  // 2 bytes of flags
  /** Is a splitfile */
  boolean splitfile;

  /** Is a DBR */
  boolean dbr;

  /** No MIME type; on by default as not all doctypes have MIME */
  boolean noMIME = true;

  /** Compressed MIME type */
  boolean compressedMIME;

  /** Has extra client-metadata */
  boolean extraMetadata;

  /** Keys stored in full (otherwise assumed to be CHKs) */
  boolean fullKeys;

  static final short FLAGS_SPLITFILE = 1;
  static final short FLAGS_DBR = 2; // not supported
  static final short FLAGS_NO_MIME = 4;
  static final short FLAGS_COMPRESSED_MIME = 8;
  static final short FLAGS_EXTRA_METADATA = 16;
  static final short FLAGS_FULL_KEYS = 32;
  // static final short FLAGS_SPLIT_USE_LENGTHS = 64; reserved (not supported). If a new flag is
  // required in future, consider reassigning this placeholder.
  static final short FLAGS_COMPRESSED = 128;
  static final short FLAGS_TOP_SIZE = 256;
  static final short FLAGS_HASHES = 512;
  // If parsed version = 1 and splitfile is set and hashes exist, we create the splitfile key from
  // the hashes.
  // This flag overrides this behaviour and reads a key anyway.
  static final short FLAGS_SPECIFY_SPLITFILE_KEY = 1024;
  // We can specify a hash just for this layer as well as hashes for the final content in a
  // multi-layer splitfile.
  static final short FLAGS_HASH_THIS_LAYER = 2048;
  private static final byte[] SPLITKEY = "SPLITKEY".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CROSS_SEGMENT_SEED =
      "CROSS_SEGMENT_SEED".getBytes(StandardCharsets.UTF_8);

  /**
   * Container archive type
   *
   * @see ARCHIVE_TYPE
   */
  ARCHIVE_TYPE archiveType;

  /**
   * Compressed splitfile codec
   *
   * @see COMPRESSOR_TYPE
   */
  COMPRESSOR_TYPE compressionCodec;

  /** The length of the splitfile */
  long dataLength;

  /** The decompressed length of the compressed data */
  long decompressedLength;

  /** The MIME type, as a string */
  String mimeType;

  /**
   * The compressed MIME type - lookup index for the MIME types table. Must be between 0 and 32767.
   */
  short compressedMIMEValue;

  boolean hasCompressedMIMEParams;
  short compressedMIMEParams;

  /** The simple redirect key */
  FreenetURI simpleRedirectKey;

  /**
   * Metadata is sometimes used as a key in hashtables. Therefore it needs a persistent hashCode.
   */
  private final int hashCode;

  SplitfileAlgorithm splitfileAlgorithm;

  public enum SplitfileAlgorithm {
    NONREDUNDANT((short) 0),
    ONION_STANDARD((short) 1);

    public final short code;

    SplitfileAlgorithm(short code) {
      this.code = code;
    }

    public static SplitfileAlgorithm getByCode(short s) {
      if (s < 0 || s >= values().length) throw new IllegalArgumentException("Bad splitfile code");
      return values()[s];
    }
  }

  public static final int MAX_SIZE_IN_MANIFEST = Short.MAX_VALUE;

  /** Splitfile parameters */
  byte[] splitfileParams;

  /** This includes cross-check blocks. */
  int splitfileBlocks;

  int splitfileCheckBlocks;
  ClientCHK[] splitfileDataKeys;
  ClientCHK[] splitfileCheckKeys;

  /** Used if splitfile single crypto key is enabled */
  byte splitfileSingleCryptoAlgorithm;

  byte[] splitfileSingleCryptoKey;
  // If false, the splitfile key can be computed from the hashes. If true, it must be specified.
  private boolean specifySplitfileKey;

  /** As opposed to hashes of the final content. */
  byte[] hashThisLayerOnly;

  int blocksPerSegment;
  int checkBlocksPerSegment;
  int segmentCount;
  int deductBlocksFromSegments;
  int crossCheckBlocks;
  SplitFileSegmentKeys[] segments;
  CompatibilityMode minCompatMode = CompatibilityMode.COMPAT_UNKNOWN;
  CompatibilityMode maxCompatMode = CompatibilityMode.COMPAT_UNKNOWN;

  // Manifests
  /** Manifest entries by name */
  HashMap<String, Metadata> manifestEntries;

  /** Archive internal redirect: name of file in archive SympolicShortLink: Target name */
  String targetName;

  ClientMetadata clientMetadata;
  private HashResult[] hashes;

  public final long topSize;
  public final long topCompressedSize;
  public final int topBlocksRequired;
  public final int topBlocksTotal;
  public final boolean topDontCompress;
  public final CompatibilityMode topCompatibilityMode;

  // No static initialization required.

  /**
   * Copy constructor.
   *
   * <p>Performs a field-by-field copy equivalent to the previous {@code clone()} behavior:
   *
   * <ul>
   *   <li>Primitives, enums, strings, and references are copied as-is (shallow copy).
   *   <li>{@code segments}, {@code hashes}, {@code manifestEntries}, and {@code clientMetadata} are
   *       deep-copied to produce independent structures.
   *   <li>The persistent {@link #hashCode} and the {@code top*} fields are preserved exactly.
   * </ul>
   *
   * @param orig Source instance to copy.
   * @throws NullPointerException if {@code orig} is {@code null}.
   */
  public Metadata(Metadata orig) {
    if (orig == null) throw new NullPointerException("orig");
    // Preserve persistent identity/hash and top-level immutable values.
    this.hashCode = orig.hashCode;
    this.topSize = orig.topSize;
    this.topCompressedSize = orig.topCompressedSize;
    this.topBlocksRequired = orig.topBlocksRequired;
    this.topBlocksTotal = orig.topBlocksTotal;
    this.topDontCompress = orig.topDontCompress;
    this.topCompatibilityMode = orig.topCompatibilityMode;

    // Shallow copy simple/reference fields (matches prior clone() + shallow semantics).
    this.resolvedURI = orig.resolvedURI;
    this.resolvedName = orig.resolvedName;
    this.documentType = orig.documentType;
    this.parsedVersion = orig.parsedVersion;
    this.splitfile = orig.splitfile;
    this.dbr = orig.dbr;
    this.noMIME = orig.noMIME;
    this.compressedMIME = orig.compressedMIME;
    this.extraMetadata = orig.extraMetadata;
    this.fullKeys = orig.fullKeys;
    this.archiveType = orig.archiveType;
    this.compressionCodec = orig.compressionCodec;
    this.dataLength = orig.dataLength;
    this.decompressedLength = orig.decompressedLength;
    this.mimeType = orig.mimeType;
    this.compressedMIMEValue = orig.compressedMIMEValue;
    this.hasCompressedMIMEParams = orig.hasCompressedMIMEParams;
    this.compressedMIMEParams = orig.compressedMIMEParams;
    this.simpleRedirectKey = orig.simpleRedirectKey;
    this.splitfileAlgorithm = orig.splitfileAlgorithm;
    this.splitfileParams = orig.splitfileParams;
    this.splitfileBlocks = orig.splitfileBlocks;
    this.splitfileCheckBlocks = orig.splitfileCheckBlocks;
    this.splitfileDataKeys = orig.splitfileDataKeys;
    this.splitfileCheckKeys = orig.splitfileCheckKeys;
    this.splitfileSingleCryptoAlgorithm = orig.splitfileSingleCryptoAlgorithm;
    this.splitfileSingleCryptoKey = orig.splitfileSingleCryptoKey;
    this.specifySplitfileKey = orig.specifySplitfileKey;
    this.hashThisLayerOnly = orig.hashThisLayerOnly;
    this.blocksPerSegment = orig.blocksPerSegment;
    this.checkBlocksPerSegment = orig.checkBlocksPerSegment;
    this.segmentCount = orig.segmentCount;
    this.deductBlocksFromSegments = orig.deductBlocksFromSegments;
    this.crossCheckBlocks = orig.crossCheckBlocks;
    this.minCompatMode = orig.minCompatMode;
    this.maxCompatMode = orig.maxCompatMode;
    this.targetName = orig.targetName;

    // Deep copy selected structures.
    if (orig.segments != null) {
      this.segments = new SplitFileSegmentKeys[orig.segments.length];
      for (int i = 0; i < this.segments.length; i++) {
        this.segments[i] = new SplitFileSegmentKeys(orig.segments[i]);
      }
    }
    if (orig.hashes != null) {
      this.hashes = new HashResult[orig.hashes.length];
      for (int i = 0; i < this.hashes.length; i++) this.hashes[i] = orig.hashes[i].clone();
    }
    if (orig.manifestEntries != null) {
      this.manifestEntries = HashMap.newHashMap(orig.manifestEntries.size());
      for (Map.Entry<String, Metadata> entry : orig.manifestEntries.entrySet()) {
        Metadata value = entry.getValue();
        this.manifestEntries.put(entry.getKey(), value == null ? null : new Metadata(value));
      }
    }
    if (orig.clientMetadata != null) {
      this.clientMetadata = ClientMetadata.copyOf(orig.clientMetadata);
    }
  }

  /**
   * Copy factory for callers preferring a named method over a constructor.
   *
   * @param orig Source instance to copy.
   * @return a deep copy following the same rules as {@link #Metadata(Metadata)}.
   */
  public static Metadata copyOf(Metadata orig) {
    return new Metadata(orig);
  }

  /**
   * Parse a block of bytes into a Metadata structure. Constructor method because of need to catch
   * impossible exceptions.
   *
   * @throws MetadataParseException If the metadata is invalid.
   */
  public static Metadata construct(byte[] data) throws MetadataParseException {
    try {
      return new Metadata(data);
    } catch (IOException e) {
      throw (MetadataParseException) new MetadataParseException("Caught " + e).initCause(e);
    }
  }

  /**
   * Parse a bucket of data into a Metadata structure.
   *
   * @throws MetadataParseException If the parsing failed because of invalid metadata.
   * @throws IOException If we could not read the metadata from the bucket.
   */
  public static Metadata construct(Bucket data) throws MetadataParseException, IOException {
    Metadata m;
    try (InputStream is = data.getInputStream();
        DataInputStream dis = new DataInputStream(is)) {
      m = new Metadata(dis, data.size());
    }
    return m;
  }

  /**
   * Parse some metadata from a byte[].
   *
   * @throws IOException If the data is incomplete, or something wierd happens.
   * @throws MetadataParseException
   */
  private Metadata(byte[] data) throws IOException, MetadataParseException {
    this(new DataInputStream(new ByteArrayInputStream(data)), data.length);
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  @SuppressWarnings("RedundantMethodOverride")
  public boolean equals(Object obj) {
    return this == obj;
  }

  /**
   * Parse some metadata from a DataInputStream
   *
   * @throws IOException If an I/O error occurs, or the data is incomplete.
   */
  public Metadata(DataInputStream dis, long length) throws IOException, MetadataParseException {
    hashCode = super.hashCode();
    readMagicVersionAndDocType(dis);

    HeaderState header = readFlagsAndHashes(dis);
    TopInfo top = readTopBlocksInfo(dis, header.hasTopBlocks);
    this.topSize = top.size;
    this.topCompressedSize = top.compressedSize;
    this.topBlocksRequired = top.blocksRequired;
    this.topBlocksTotal = top.blocksTotal;
    this.topDontCompress = top.dontCompress;
    this.topCompatibilityMode = top.compatMode;

    readArchiveTypeIfNeeded(dis);

    readSplitfileCryptoAndLengthIfNeeded(dis);
    readCompressionFieldsIfNeeded(dis, header.compressed);
    readMime(dis);
    failOnUnsupportedDBR();
    readAndDiscardExtraClientMetadata(dis);
    clientMetadata = new ClientMetadata(mimeType);

    // Parsing continues below.
    readSimpleRedirectOrArchiveKeyIfNeeded(dis);

    // Remaining tail sections
    readManifestIfSimple(dis, length);
    readArchiveInternalOrShortlinkIfNeeded(dis);

    // Splitfile header and layout come after the above sections in the serialized form.
    if (splitfile) {
      parseSplitfileHeaderAndLayout(dis);
      readSplitfileKeys(dis);
    }
  }

  public static byte[] getCryptoKey(HashResult[] hashes) {
    if (hashes == null || hashes.length == 0 || !HashResult.contains(hashes, HashType.SHA256))
      throw new IllegalArgumentException(
          "No hashes in getCryptoKey - need hashes to generate splitfile key!");
    byte[] hash = HashResult.get(hashes, HashType.SHA256);
    return getCryptoKey(hash);
  }

  public static byte[] getCryptoKey(byte[] hash) {
    // This is exactly the same algorithm used by e.g. JFK for generating multiple session keys from
    // a single generated value.
    // The only difference is we use a constant of more than one byte's length here, to avoid having
    // to keep a registry.
    MessageDigest md = SHA256.getMessageDigest();
    md.update(hash);
    md.update(SPLITKEY);
    return md.digest();
  }

  public static byte[] getCrossSegmentSeed(HashResult[] hashes, byte[] hashThisLayerOnly) {
    byte[] hash = hashThisLayerOnly;
    if (hash == null) {
      if (hashes == null || hashes.length == 0 || !HashResult.contains(hashes, HashType.SHA256))
        throw new IllegalArgumentException(
            "No hashes in getCryptoKey - need hashes to generate splitfile key!");
      hash = HashResult.get(hashes, HashType.SHA256);
    }
    return getCrossSegmentSeed(hash);
  }

  public static byte[] getCrossSegmentSeed(byte[] hash) {
    // This is exactly the same algorithm used by e.g. JFK for generating multiple session keys from
    // a single generated value.
    // The only difference is we use a constant of more than one byte's length here, to avoid having
    // to keep a registry.
    MessageDigest md = SHA256.getMessageDigest();
    md.update(hash);
    md.update(CROSS_SEGMENT_SEED);
    return md.digest();
  }

  /** Create an empty Metadata object */
  private Metadata() {
    hashCode = super.hashCode();
    hashes = null;
    // Should be followed by addRedirectionManifest
    topSize = 0;
    topCompressedSize = 0;
    topBlocksRequired = 0;
    topBlocksTotal = 0;
    topDontCompress = false;
    topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
  }

  /**
   * Create a Metadata object and add data for redirection to it.
   *
   * @param dir A map of names (string) to either files (same string) or directories (more
   *     HashMap's)
   * @throws MalformedURLException One of the URI:s were malformed
   */
  private void addRedirectionManifest(Map<String, Object> dir) throws MalformedURLException {
    // Simple manifest - contains actual redirects.
    // Not archive manifest, which is basically a redirect.
    documentType = DocumentType.SIMPLE_MANIFEST;
    noMIME = true;
    manifestEntries = new HashMap<>();
    for (Map.Entry<String, Object> entry : dir.entrySet()) {
      String key = entry.getKey().intern();
      Object o = entry.getValue();
      Metadata target;
      if (o instanceof String string) {
        // External redirect
        FreenetURI uri = new FreenetURI(string);
        target = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, uri, null);
      } else if (o instanceof Map) {
        target = new Metadata();
        target.addRedirectionManifest(Metadata.forceMap(o));
      } else throw new IllegalArgumentException("Not String nor Map: " + o);
      manifestEntries.put(key, target);
    }
  }

  /**
   * Create a Metadata object and add data for redirection to it.
   *
   * @param dir A map of names (string) to either files (same string) or directories (more
   *     HashMap's)
   * @throws MalformedURLException One of the URI:s were malformed
   */
  public static Metadata mkRedirectionManifest(Map<String, Object> dir)
      throws MalformedURLException {
    Metadata ret = new Metadata();
    ret.addRedirectionManifest(dir);
    return ret;
  }

  /**
   * Create a Metadata object and add manifest entries from the given map. The map can contain
   * either string -> Metadata, or string -> map, the latter indicating subdirs.
   */
  public static Metadata mkRedirectionManifestWithMetadata(Map<String, Object> dir) {
    Metadata ret = new Metadata();
    ret.addRedirectionManifestWithMetadata(dir);
    return ret;
  }

  private void addRedirectionManifestWithMetadata(Map<String, Object> dir) {
    // Simple manifest - contains actual redirects.
    // Not archive manifest, which is basically a redirect.
    documentType = DocumentType.SIMPLE_MANIFEST;
    noMIME = true;
    manifestEntries = new HashMap<>();
    for (Map.Entry<String, Object> entry : dir.entrySet()) {
      String key = entry.getKey().intern();
      if (key.indexOf('/') != -1)
        throw new IllegalArgumentException(
            "Slashes in simple redirect manifest filenames! (slashes denote sub-manifests): "
                + key);
      putManifestEntryWithMetadata(key, entry.getValue());
    }
  }

  private void putManifestEntryWithMetadata(String key, Object value) {
    if (value instanceof Metadata data) {
      if (LOG.isTraceEnabled()) LOG.trace("Putting metadata for {}", key);
      manifestEntries.put(key, data);
      return;
    }
    if (value instanceof Map) {
      if (key.isEmpty()) {
        LOG.error(
            "Creating a subdirectory called \"\" - it will not be possible to access this through"
                + " fproxy!",
            new Exception("error"));
      }
      Map<String, Object> hm = Metadata.forceMap(value);
      if (LOG.isTraceEnabled()) LOG.trace("Making metadata map for {}", key);
      Metadata subMap = mkRedirectionManifestWithMetadata(hm);
      manifestEntries.put(key, subMap);
      if (LOG.isTraceEnabled()) LOG.trace("Putting metadata map for {}", key);
    }
  }

  /**
   * Create a Metadata object for an archive which does not have its own metadata.
   *
   * @param dir A map of names (string) to either files (same string) or directories (more
   *     HashMap's)
   */
  Metadata(Map<String, Object> dir, String prefix) {
    hashCode = super.hashCode();
    hashes = null;
    // Simple manifest - contains actual redirects.
    // Not archive manifest, which is basically a redirect.
    documentType = DocumentType.SIMPLE_MANIFEST;
    noMIME = true;
    mimeType = null;
    clientMetadata = new ClientMetadata();
    manifestEntries = new HashMap<>();
    for (Map.Entry<String, Object> entry : dir.entrySet()) {
      String key = entry.getKey().intern();
      Object o = entry.getValue();
      Metadata target;
      if (o instanceof String) {
        // Archive internal redirect
        target =
            new Metadata(
                DocumentType.ARCHIVE_INTERNAL_REDIRECT,
                null,
                null,
                prefix + key,
                new ClientMetadata(DefaultMIMETypes.guessMIMEType(key, false)));
      } else if (o instanceof HashMap) {
        target = new Metadata(Metadata.forceMap(o), prefix + key + "/");
      } else throw new IllegalArgumentException("Not String nor HashMap: " + o);
      manifestEntries.put(key, target);
    }
    topSize = 0;
    topCompressedSize = 0;
    topBlocksRequired = 0;
    topBlocksTotal = 0;
    topDontCompress = false;
    topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
  }

  /**
   * Create a really simple Metadata object.
   *
   * @param docType The document type. Must be something that takes a single argument. At the moment
   *     this means ARCHIVE_INTERNAL_REDIRECT.
   * @param arg The argument; in the case of ARCHIVE_INTERNAL_REDIRECT, the filename in the archive
   *     to read from.
   */
  public Metadata(
      DocumentType docType,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressionCodec,
      String arg,
      ClientMetadata cm) {
    hashCode = super.hashCode();
    if ((docType == DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        || (docType == DocumentType.SYMBOLIC_SHORTLINK)) {
      documentType = docType;
      this.archiveType = archiveType;
      // Determine MIME type
      this.clientMetadata = cm;
      this.compressionCodec = compressionCodec;
      if (cm != null) this.setMIMEType(cm.getMIMEType());
      targetName = arg;
      while (true) {
        if (targetName.isEmpty())
          throw new IllegalArgumentException("Invalid target name is empty: \"" + arg + "\"");
        if (targetName.charAt(0) == '/') {
          targetName = targetName.substring(1);
          LOG.error(
              "Stripped initial slash from archive internal redirect on creating metadata: \"{}\"",
              arg,
              new Exception("debug"));
        } else break;
      }
    } else throw new IllegalArgumentException();
    hashes = null;
    topSize = 0;
    topCompressedSize = 0;
    topBlocksRequired = 0;
    topBlocksTotal = 0;
    topDontCompress = false;
    topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
  }

  /**
   * Create a Metadata redircet object that points to resolved metadata inside container. docType =
   * ARCHIVE_METADATA_REDIRECT
   *
   * @param name the filename in the archive to read from, must be ".metadata-N" scheme.
   */
  private Metadata(DocumentType docType, String name) {
    hashCode = super.hashCode();
    noMIME = true;
    if (docType == DocumentType.ARCHIVE_METADATA_REDIRECT) {
      documentType = docType;
      targetName = name;
      while (true) {
        if (targetName.isEmpty())
          throw new IllegalArgumentException("Invalid target name is empty: \"" + name + "\"");
        if (targetName.charAt(0) == '/') {
          targetName = targetName.substring(1);
          LOG.error(
              "Stripped initial slash from archive internal redirect on creating metadata: \"{}\"",
              name,
              new Exception("debug"));
        } else break;
      }
    } else throw new IllegalArgumentException();
    hashes = null;
    topSize = 0;
    topCompressedSize = 0;
    topBlocksRequired = 0;
    topBlocksTotal = 0;
    topDontCompress = false;
    topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
  }

  public Metadata(
      DocumentType docType,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressionCodec,
      FreenetURI uri,
      ClientMetadata cm) {
    this(
        docType,
        archiveType,
        compressionCodec,
        uri,
        cm,
        0,
        0,
        0,
        0,
        false,
        CompatibilityMode.COMPAT_UNKNOWN,
        null);
  }

  /**
   * Create another kind of simple Metadata object (a redirect or similar object).
   *
   * @param docType The document type.
   * @param uri The URI pointed to.
   * @param cm The client metadata, if any.
   */
  public Metadata(
      DocumentType docType,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressionCodec,
      FreenetURI uri,
      ClientMetadata cm,
      long origDataLength,
      long origCompressedDataLength,
      int reqBlocks,
      int totalBlocks,
      boolean topDontCompress,
      CompatibilityMode topCompatibilityMode,
      HashResult[] hashes) {
    if (topCompatibilityMode == CompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("Invalid top compatibility mode: COMPAT_CURRENT");
    }
    hashCode = super.hashCode();
    if (hashes != null && hashes.length == 0) throw new IllegalArgumentException();
    this.hashes = hashes;
    initSimpleRedirectOrArchive(docType, archiveType, compressionCodec, cm, uri);
    TopLayerInit tli =
        computeTopLayerInit(
            origDataLength,
            origCompressedDataLength,
            reqBlocks,
            totalBlocks,
            topDontCompress,
            topCompatibilityMode,
            hashes);
    this.topSize = tli.size;
    this.topCompressedSize = tli.compressedSize;
    this.topBlocksRequired = tli.blocksRequired;
    this.topBlocksTotal = tli.blocksTotal;
    this.topDontCompress = tli.dontCompress;
    this.topCompatibilityMode = tli.compatMode;
    parsedVersion = tli.parsedVersion;
  }

  private void initSimpleRedirectOrArchive(
      DocumentType docType,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressionCodec,
      ClientMetadata cm,
      FreenetURI uri) {
    if ((docType == DocumentType.SIMPLE_REDIRECT) || (docType == DocumentType.ARCHIVE_MANIFEST)) {
      documentType = docType;
      this.archiveType = archiveType;
      this.compressionCodec = compressionCodec;
      clientMetadata = cm;
      if ((cm != null) && !cm.isTrivial()) {
        setMIMEType(cm.getMIMEType());
      } else {
        setMIMEType(DefaultMIMETypes.DEFAULT_MIME_TYPE);
        noMIME = true;
      }
      if (uri == null) throw new NullPointerException();
      simpleRedirectKey = uri;
      if (!(uri.getKeyType().equals("CHK") && !uri.hasMetaStrings())) fullKeys = true;
      return;
    }
    throw new IllegalArgumentException();
  }

  private TopLayerInit computeTopLayerInit(
      long origDataLength,
      long origCompressedDataLength,
      int reqBlocks,
      int totalBlocks,
      boolean topDontCompress,
      CompatibilityMode topCompatibilityMode,
      HashResult[] hashes) {
    if (origDataLength != 0
        || origCompressedDataLength != 0
        || reqBlocks != 0
        || totalBlocks != 0
        || hashes != null) {
      return new TopLayerInit(
          origDataLength,
          origCompressedDataLength,
          reqBlocks,
          totalBlocks,
          topDontCompress,
          topCompatibilityMode,
          (short) 1);
    } else {
      return new TopLayerInit(0, 0, 0, 0, false, CompatibilityMode.COMPAT_UNKNOWN, (short) 0);
    }
  }

  /**
   * Create metadata for a splitfile.
   *
   * @param algo The splitfile FEC algorithm.
   * @param dataURIs The data URIs, including cross-check blocks for each segment.
   * @param checkURIs The check URIs.
   * @param segmentSize The number of data blocks in a typical segment. Does not include cross-check
   *     blocks.
   * @param checkSegmentSize The number of check blocks in a typical segment. Does not include
   *     cross-check blocks.
   * @param deductBlocksFromSegments If this is set, the last few segments will lose a data block,
   *     so that all the segments are the same size to within 1 block. In older splitfiles, the last
   *     segment could be significantly smaller, and this impacted on retrievability.
   * @param cm The client metadata i.e. MIME type.
   * @param dataLength The size of the data that this specific splitfile encodes (as opposed to the
   *     final data), after compression if necessary.
   * @param archiveType The archive type, if the splitfile is a container.
   * @param compressionCodec The compression codec used to compress the data.
   * @param decompressedLength The length of this specific splitfile's data after it has been
   *     decompressed.
   * @param isMetadata If true, the splitfile is multi-level metadata i.e. it encodes a bucket full
   *     of metadata. This usually happens for really big splitfiles, which can be a pyramid of one
   *     block with metadata for a splitfile full of metadata, that metadata then encodes another
   *     splitfile full of metadata, etc. Hence we can support very large files.
   * @param hashes Various hashes of <b>the final data</b>. There should always be at least an
   *     SHA256 hash, unless we are inserting with an old compatibility mode.
   * @param hashThisLayerOnly Hash of the data in this layer (before compression). Separate from
   *     hashes of the final data. Not currently verified.
   * @param origDataSize The size of the final/original data.
   * @param origCompressedDataSize The size of the final/original data after it was compressed.
   * @param requiredBlocks The number of blocks required on fetch to reconstruct the final data.
   *     Hence as soon as we have the top splitfile metadata (i.e. hopefully in the top block), we
   *     can show an accurate progress bar.
   * @param totalBlocks The total number of blocks inserted during the whole insert for the
   *     final/original data.
   * @param topDontCompress Whether dontCompress was enabled. This allows us to figure out reinsert
   *     settings more quickly.
   * @param topCompatibilityMode The compatibility mode applying to the insert. This allows us to
   *     figure out reinsert settings more quickly.
   * @param splitfileCryptoAlgorithm The block level crypto algorithm for all the blocks in the
   *     splitfile.
   * @param splitfileCryptoKey The single encryption key used by all blocks in the splitfile. Older
   *     splitfiles don't have this so have to specify the full keys; newer splitfiles just specify
   *     the 32 byte routing key for each data or check key.
   * @param specifySplitfileKey If false, the splitfile crypto key has been automatically computed
   *     from the final or this-layer data hash. If true, it has been specified explicitly, either
   *     because it is randomly generated (this significantly improves security against mobile
   *     attacker source tracing and is the default for splitfiles under SSKs), or because a file is
   *     being reinserted.
   * @param crossSegmentBlocks The number of cross-check blocks. If this is specified, we are using
   *     cross-segment redundancy. This greatly improves reliability on files over 80MB, see bug
   *     #3370.
   */
  public Metadata(
      SplitfileAlgorithm algo,
      ClientCHK[] dataURIs,
      ClientCHK[] checkURIs,
      int segmentSize,
      int checkSegmentSize,
      int deductBlocksFromSegments,
      ClientMetadata cm,
      long dataLength,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressionCodec,
      long decompressedLength,
      boolean isMetadata,
      HashResult[] hashes,
      byte[] hashThisLayerOnly,
      long origDataSize,
      long origCompressedDataSize,
      int requiredBlocks,
      int totalBlocks,
      boolean topDontCompress,
      CompatibilityMode topCompatibilityMode,
      byte splitfileCryptoAlgorithm,
      byte[] splitfileCryptoKey,
      boolean specifySplitfileKey,
      int crossSegmentBlocks) {
    if (topCompatibilityMode == CompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("Invalid top compatibility mode: COMPAT_CURRENT");
    }
    hashCode = super.hashCode();
    this.hashes = hashes;
    this.hashThisLayerOnly = hashThisLayerOnly;
    if (hashThisLayerOnly != null && hashThisLayerOnly.length != 32)
      throw new IllegalArgumentException();
    chooseDocTypeForSplitfile(isMetadata, archiveType);
    initSplitfileCore(
        algo,
        dataURIs,
        checkURIs,
        cm,
        compressionCodec,
        dataLength,
        decompressedLength,
        splitfileCryptoKey,
        hashes,
        topCompatibilityMode,
        deductBlocksFromSegments);
    TopLayerInit tli2 =
        computeTopLayerInit(
            origDataSize,
            origCompressedDataSize,
            requiredBlocks,
            totalBlocks,
            topDontCompress,
            topCompatibilityMode,
            hashes);
    this.topSize = tli2.size;
    this.topCompressedSize = tli2.compressedSize;
    this.topBlocksRequired = tli2.blocksRequired;
    this.topBlocksTotal = tli2.blocksTotal;
    this.topDontCompress = tli2.dontCompress;
    this.topCompatibilityMode = tli2.compatMode;
    // Preserve the higher version requirement: initSplitfileCore() may have
    // promoted parsedVersion to 1 based on compatibility mode even when the
    // top-layer has no hashes/blocks (tli2.parsedVersion == 0). Do not
    // downgrade, or we would omit splitfile crypto parameters on serialization.
    parsedVersion = (short) Math.max(parsedVersion, tli2.parsedVersion);
    buildSplitfileParamsBytes(
        segmentSize,
        checkSegmentSize,
        deductBlocksFromSegments,
        crossSegmentBlocks,
        splitfileCryptoAlgorithm,
        splitfileCryptoKey,
        specifySplitfileKey);
  }

  private void chooseDocTypeForSplitfile(boolean isMetadata, ARCHIVE_TYPE archiveType) {
    if (isMetadata) {
      documentType = DocumentType.MULTI_LEVEL_METADATA;
    } else if (archiveType != null) {
      documentType = DocumentType.ARCHIVE_MANIFEST;
      this.archiveType = archiveType;
    } else {
      documentType = DocumentType.SIMPLE_REDIRECT;
    }
    splitfile = true;
  }

  private void initSplitfileCore(
      SplitfileAlgorithm algo,
      ClientCHK[] dataURIs,
      ClientCHK[] checkURIs,
      ClientMetadata cm,
      COMPRESSOR_TYPE compressionCodec,
      long dataLengthValue,
      long decompressedLength,
      byte[] splitfileCryptoKey,
      HashResult[] hashes,
      CompatibilityMode topCompatibilityModeParam,
      int deductBlocksFromSegments) {
    splitfileAlgorithm = algo;
    this.dataLength = dataLengthValue;
    this.compressionCodec = compressionCodec;
    splitfileBlocks = dataURIs.length;
    splitfileCheckBlocks = checkURIs.length;
    splitfileDataKeys = dataURIs;
    if (keysInvalid(splitfileDataKeys)) throw new IllegalArgumentException("Invalid data keys");
    splitfileCheckKeys = checkURIs;
    if (keysInvalid(splitfileCheckKeys)) throw new IllegalArgumentException("Invalid check keys");
    clientMetadata = cm;
    this.compressionCodec = compressionCodec;
    this.decompressedLength = decompressedLength;
    if (cm != null) setMIMEType(cm.getMIMEType());
    else setMIMEType(DefaultMIMETypes.DEFAULT_MIME_TYPE);
    if (topCompatibilityModeParam.ordinal() < CompatibilityMode.COMPAT_1255.ordinal()) {
      if (splitfileCryptoKey != null) throw new IllegalArgumentException();
      if (hashes != null) throw new IllegalArgumentException();
      if (deductBlocksFromSegments != 0) throw new IllegalArgumentException();
      parsedVersion = 0;
    } else {
      if (splitfileCryptoKey == null) throw new IllegalArgumentException();
      parsedVersion = 1;
    }
  }

  // Top fields are final; compute values then assign once in constructors.

  private void buildSplitfileParamsBytes(
      int segmentSize,
      int checkSegmentSize,
      int deductBlocksFromSegments,
      int crossSegmentBlocks,
      byte splitfileCryptoAlgorithm,
      byte[] splitfileCryptoKey,
      boolean specifySplitfileKey) {
    if (parsedVersion == 0) {
      splitfileParams = Fields.intsToBytes(new int[] {segmentSize, checkSegmentSize});
      return;
    }
    boolean deductBlocks = (deductBlocksFromSegments != 0);
    short mode;
    int len = 10;
    if (crossSegmentBlocks == 0) {
      mode =
          deductBlocks ? SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS : SPLITFILE_PARAMS_SIMPLE_SEGMENT;
      if (deductBlocks) len += 4;
    } else {
      mode = SPLITFILE_PARAMS_CROSS_SEGMENT;
      len += 8;
    }
    splitfileParams = new byte[len];
    byte[] b = Fields.shortToBytes(mode);
    System.arraycopy(b, 0, splitfileParams, 0, 2);
    // Note: for insert-built Metadata, params contain values but keys are handled elsewhere.
    b =
        switch (mode) {
          case SPLITFILE_PARAMS_CROSS_SEGMENT ->
              Fields.intsToBytes(
                  new int[] {
                    segmentSize, checkSegmentSize, deductBlocksFromSegments, crossSegmentBlocks
                  });
          case SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS ->
              Fields.intsToBytes(
                  new int[] {segmentSize, checkSegmentSize, deductBlocksFromSegments});
          default -> Fields.intsToBytes(new int[] {segmentSize, checkSegmentSize});
        };
    System.arraycopy(b, 0, splitfileParams, 2, b.length);
    this.splitfileSingleCryptoAlgorithm = splitfileCryptoAlgorithm;
    this.splitfileSingleCryptoKey = splitfileCryptoKey;
    this.specifySplitfileKey = specifySplitfileKey;
    if (splitfileCryptoKey == null)
      throw new IllegalArgumentException("Splitfile with parsed version 1 must have a crypto key");
    // Segments layout is managed elsewhere when needed.
  }

  private boolean keysInvalid(ClientCHK[] keys) {
    for (ClientCHK key : keys) if (key.getNodeCHK().getRoutingKey() == null) return true;
    return false;
  }

  /** Set the MIME type to a string. Compresses it if possible for transit. */
  private void setMIMEType(String type) {
    noMIME = false;
    short s = DefaultMIMETypes.byName(type);
    if (s >= 0) {
      compressedMIME = true;
      compressedMIMEValue = s;
    } else {
      compressedMIME = false;
    }
    mimeType = type;
  }

  /**
   * Write the data to a byte array.
   *
   * @throws MetadataUnresolvedException
   */
  public byte[] writeToByteArray() throws MetadataUnresolvedException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      writeTo(dos);
    } catch (IOException e) {
      throw new java.io.UncheckedIOException("Could not write to byte array", e);
    }
    return baos.toByteArray();
  }

  public long writtenLength() throws MetadataUnresolvedException {
    try (CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
        DataOutputStream dos = new DataOutputStream(cos)) {
      writeTo(dos);
      return cos.written();
    } catch (IOException e) {
      throw new java.io.UncheckedIOException("Could not write to CountedOutputStream", e);
    }
  }

  /**
   * Read a key using the current settings.
   *
   * @throws IOException
   * @throws MalformedURLException If the key could not be read due to an error in parsing the key.
   *     REDFLAG: May want to recover from these in future, hence the short length.
   */
  private FreenetURI readKey(DataInputStream dis) throws IOException {
    // Read URL
    if (fullKeys) {
      return FreenetURI.readFullBinaryKeyWithLength(dis);
    } else {
      return ClientCHK.readRawBinaryKey(dis).getURI();
    }
  }

  /**
   * Write a key using the current settings.
   *
   * @throws IOException
   * @throws MalformedURLException If an error in the key itself prevented it from being written.
   */
  private void writeKey(DataOutputStream dos, FreenetURI freenetURI) throws IOException {
    if (fullKeys) {
      freenetURI.writeFullBinaryKeyWithLength(dos);
    } else {
      String[] meta = freenetURI.getAllMetaStrings();
      if ((meta != null) && (meta.length > 0)) throw new MalformedURLException("Not a plain CHK");
      BaseClientKey key = BaseClientKey.getBaseKey(freenetURI);
      if (key instanceof ClientCHK hK) {
        hK.writeRawBinaryKey(dos);
      } else throw new IllegalArgumentException("Full keys must be enabled to write non-CHKs");
    }
  }

  private void writeCHK(DataOutputStream dos, ClientCHK chk) throws IOException {
    if (fullKeys) {
      throw new UnsupportedOperationException("Full keys not supported on splitfiles");
    } else {
      chk.writeRawBinaryKey(dos);
    }
  }

  /** Is a manifest? */
  public boolean isSimpleManifest() {
    return documentType == DocumentType.SIMPLE_MANIFEST;
  }

  /**
   * Get the sub-document in a manifest file with the given name.
   *
   * @throws MetadataParseException
   */
  public Metadata getDocument(String name) {
    return manifestEntries.get(name);
  }

  /**
   * Return and remove a specific document. Used in persistent requests so that when removeFrom() is
   * called, the default document won't be removed, since it is being processed.
   */
  public Metadata grabDocument(String name) {
    return manifestEntries.remove(name);
  }

  /**
   * The default document is the one which has an empty name.
   *
   * @throws MetadataParseException
   */
  public Metadata getDefaultDocument() {
    return getDocument("");
  }

  /**
   * Return and remove the default document. Used in persistent requests so that when removeFrom()
   * is called, the default document won't be removed, since it is being processed.
   */
  public Metadata grabDefaultDocument() {
    return grabDocument("");
  }

  /**
   * Get all documents in the manifest (ignores default doc).
   *
   * @throws MetadataParseException
   */
  public Map<String, Metadata> getDocuments() {
    HashMap<String, Metadata> docs = new HashMap<>();
    for (Map.Entry<String, Metadata> entry : manifestEntries.entrySet()) {
      String st = entry.getKey();
      if (!st.isEmpty()) docs.put(st, entry.getValue());
    }
    return docs;
  }

  /** Does the metadata point to a single URI? */
  public boolean isSingleFileRedirect() {
    return ((!splitfile)
        && ((documentType == DocumentType.SIMPLE_REDIRECT)
            || (documentType == DocumentType.MULTI_LEVEL_METADATA)
            || (documentType == DocumentType.ARCHIVE_MANIFEST)));
  }

  /** Return the single target of this URI. */
  public FreenetURI getSingleTarget() {
    return simpleRedirectKey;
  }

  /** Is this a Archive manifest? */
  public boolean isArchiveManifest() {
    return documentType == DocumentType.ARCHIVE_MANIFEST;
  }

  /**
   * Is this a archive internal metadata redirect?
   *
   * @return
   */
  public boolean isArchiveMetadataRedirect() {
    return documentType == DocumentType.ARCHIVE_METADATA_REDIRECT;
  }

  /**
   * Is this a Archive internal redirect?
   *
   * @return
   */
  public boolean isArchiveInternalRedirect() {
    return documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT;
  }

  /**
   * Return the name of the document referred to in the archive, if this is a archive internal
   * redirect.
   */
  public String getArchiveInternalName() {
    if ((documentType != DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        && (documentType != DocumentType.ARCHIVE_METADATA_REDIRECT))
      throw new IllegalArgumentException();
    return targetName;
  }

  /** Return the name of the document referred to in the dir, if this is a symbolic short link. */
  public String getSymbolicShortlinkTargetName() {
    if (documentType != DocumentType.SYMBOLIC_SHORTLINK) throw new IllegalArgumentException();
    return targetName;
  }

  /** Return the client metadata (MIME type etc). */
  public ClientMetadata getClientMetadata() {
    return clientMetadata;
  }

  /** Is this a splitfile manifest? */
  public boolean isSplitfile() {
    return splitfile;
  }

  /** Is this a simple splitfile? */
  @SuppressWarnings("unused")
  public boolean isSimpleSplitfile() {
    return splitfile && (documentType == DocumentType.SIMPLE_REDIRECT);
  }

  /** Is multi-level/indirect metadata? */
  public boolean isMultiLevelMetadata() {
    return documentType == DocumentType.MULTI_LEVEL_METADATA;
  }

  /** What kind of archive is it? */
  public ARCHIVE_TYPE getArchiveType() {
    return archiveType;
  }

  /**
   * Change the document type to a simple redirect. Used by the archive code to fetch split Archive
   * manifests.
   */
  public void setSimpleRedirect() {
    documentType = DocumentType.SIMPLE_REDIRECT;
  }

  /** Is this a simple redirect? (for KeyExplorer) */
  public boolean isSimpleRedirect() {
    return documentType == DocumentType.SIMPLE_REDIRECT;
  }

  /** Is noMime enabled? (for KeyExplorer) */
  @SuppressWarnings("unused")
  public boolean isNoMimeEnabled() {
    return noMIME;
  }

  /** get the resolved name (".metada-N") (for KeyExplorer) */
  @SuppressWarnings("unused")
  public String getResolvedName() {
    return resolvedName;
  }

  /** Is this a symbilic shortlink? */
  public boolean isSymbolicShortlink() {
    return documentType == DocumentType.SYMBOLIC_SHORTLINK;
  }

  /**
   * Write the metadata as binary.
   *
   * @throws IOException If an I/O error occurred while writing the data.
   * @throws MetadataUnresolvedException
   */
  public void writeTo(DataOutputStream dos) throws IOException, MetadataUnresolvedException {
    dos.writeLong(FREENET_METADATA_MAGIC);
    dos.writeShort(parsedVersion); // version
    dos.writeByte(documentType.code);
    boolean hasTopBlocks = hasTopBlocksSection();
    writeFlagsAndHashesSection(dos, hasTopBlocks);
    if (hasTopBlocks) writeTopBlocksSection(dos);
    writeArchiveTypeSection(dos);
    if (splitfile) writeSplitfileCryptoAndLengthSection(dos);
    writeCompressionAndMimeSection(dos);
    validateUnsupportedSections();
    writeKeysOrSplitfileSection(dos);
    writeSimpleManifestSection(dos);
    writeTailRedirectSection(dos);
  }

  private boolean hasTopBlocksSection() {
    return topBlocksRequired != 0
        || topBlocksTotal != 0
        || topSize != 0
        || topCompressedSize != 0
        || topCompatibilityMode != CompatibilityMode.COMPAT_UNKNOWN;
  }

  private void writeFlagsAndHashesSection(DataOutputStream dos, boolean hasTopBlocks)
      throws IOException {
    if (!haveFlags()) return;
    short flags = 0;
    if (splitfile) flags |= FLAGS_SPLITFILE;
    if (dbr) flags |= FLAGS_DBR;
    if (noMIME) flags |= FLAGS_NO_MIME;
    if (compressedMIME) flags |= FLAGS_COMPRESSED_MIME;
    if (extraMetadata) flags |= FLAGS_EXTRA_METADATA;
    if (fullKeys) flags |= FLAGS_FULL_KEYS;
    if (compressionCodec != null) flags |= FLAGS_COMPRESSED;
    if (hashes != null) flags |= FLAGS_HASHES;
    if (hasTopBlocks) {
      assert (parsedVersion >= 1);
      flags |= FLAGS_TOP_SIZE;
    }
    if (specifySplitfileKey) flags |= FLAGS_SPECIFY_SPLITFILE_KEY;
    if (hashThisLayerOnly != null) flags |= FLAGS_HASH_THIS_LAYER;
    dos.writeShort(flags);
    if (hashes != null) HashResult.write(hashes, dos);
    if (hashThisLayerOnly != null) {
      assert (hashThisLayerOnly.length == 32);
      dos.write(hashThisLayerOnly);
    }
  }

  private void writeTopBlocksSection(DataOutputStream dos) throws IOException {
    dos.writeLong(topSize);
    dos.writeLong(topCompressedSize);
    dos.writeInt(topBlocksRequired);
    dos.writeInt(topBlocksTotal);
    dos.writeBoolean(topDontCompress);
    dos.writeShort(topCompatibilityMode.code);
  }

  private void writeArchiveTypeSection(DataOutputStream dos) throws IOException {
    if (documentType != DocumentType.ARCHIVE_MANIFEST) return;
    short code = archiveType.metadataID;
    dos.writeShort(code);
  }

  private void writeSplitfileCryptoAndLengthSection(DataOutputStream dos) throws IOException {
    if (parsedVersion >= 1) {
      dos.writeByte(splitfileSingleCryptoAlgorithm);
      if (specifySplitfileKey
          || hashes == null
          || hashes.length == 0
          || !HashResult.contains(hashes, HashType.SHA256)) {
        dos.write(splitfileSingleCryptoKey);
      }
    }
    dos.writeLong(dataLength);
  }

  private void writeCompressionAndMimeSection(DataOutputStream dos) throws IOException {
    if (compressionCodec != null) {
      dos.writeShort(compressionCodec.metadataID);
      dos.writeLong(decompressedLength);
    }
    if (noMIME) return;
    if (compressedMIME) {
      int x = compressedMIMEValue;
      if (hasCompressedMIMEParams) x |= 32768;
      dos.writeShort((short) x);
      if (hasCompressedMIMEParams) dos.writeShort(compressedMIMEParams);
    } else {
      byte[] data = mimeType.getBytes(StandardCharsets.UTF_8);
      if (data.length > 255)
        throw new IllegalArgumentException(
            "MIME type too long: " + data.length + " bytes: " + mimeType);
      dos.writeByte((byte) data.length);
      dos.write(data);
    }
  }

  private void validateUnsupportedSections() {
    if (dbr) throw new UnsupportedOperationException("No DBR support yet");
    if (extraMetadata) throw new UnsupportedOperationException("No extra metadata support yet");
  }

  private void writeKeysOrSplitfileSection(DataOutputStream dos) throws IOException {
    if ((!splitfile)
        && ((documentType == DocumentType.SIMPLE_REDIRECT)
            || (documentType == DocumentType.ARCHIVE_MANIFEST))) {
      writeKey(dos, simpleRedirectKey);
      return;
    }
    if (!splitfile) return;
    writeSplitfileParamsAndCounts(dos);
    writeSplitfileKeys(dos);
  }

  private void writeSplitfileParamsAndCounts(DataOutputStream dos) throws IOException {
    dos.writeShort(splitfileAlgorithm.code);
    if (splitfileParams != null) {
      dos.writeInt(splitfileParams.length);
      dos.write(splitfileParams);
    } else {
      dos.writeInt(0);
    }
    dos.writeInt(splitfileBlocks);
    dos.writeInt(splitfileCheckBlocks);
  }

  private void writeSplitfileKeys(DataOutputStream dos) throws IOException {
    if (segments != null) {
      for (int i = 0; i < segmentCount; i++) segments[i].writeKeys(dos, false);
      for (int i = 0; i < segmentCount; i++) segments[i].writeKeys(dos, true);
      return;
    }
    if (splitfileSingleCryptoKey == null) {
      for (int i = 0; i < splitfileBlocks; i++) writeCHK(dos, splitfileDataKeys[i]);
      for (int i = 0; i < splitfileCheckBlocks; i++) writeCHK(dos, splitfileCheckKeys[i]);
    } else {
      for (int i = 0; i < splitfileBlocks; i++) dos.write(splitfileDataKeys[i].getRoutingKey());
      for (int i = 0; i < splitfileCheckBlocks; i++)
        dos.write(splitfileCheckKeys[i].getRoutingKey());
    }
  }

  private void readSplitfileKeys(DataInputStream dis) throws IOException {
    splitfileDataKeys = new ClientCHK[splitfileBlocks];
    splitfileCheckKeys = new ClientCHK[splitfileCheckBlocks];
    if (splitfileSingleCryptoKey == null) {
      for (int i = 0; i < splitfileBlocks; i++)
        splitfileDataKeys[i] = ClientCHK.readRawBinaryKey(dis);
      for (int i = 0; i < splitfileCheckBlocks; i++)
        splitfileCheckKeys[i] = ClientCHK.readRawBinaryKey(dis);
    } else {
      for (int i = 0; i < splitfileBlocks; i++) {
        byte[] rk = new byte[32];
        dis.readFully(rk);
        splitfileDataKeys[i] =
            new ClientCHK(
                rk, splitfileSingleCryptoKey, false, splitfileSingleCryptoAlgorithm, (short) -1);
      }
      for (int i = 0; i < splitfileCheckBlocks; i++) {
        byte[] rk = new byte[32];
        dis.readFully(rk);
        splitfileCheckKeys[i] =
            new ClientCHK(
                rk, splitfileSingleCryptoKey, false, splitfileSingleCryptoAlgorithm, (short) -1);
      }
    }
    // Rebuild segment structures for compatibility with existing callers.
    rebuildSegmentsFromKeys();
  }

  private void rebuildSegmentsFromKeys() {
    if (segmentCount <= 0) return;
    SplitFileSegmentKeys[] segs = new SplitFileSegmentKeys[segmentCount];
    int dataIdx = 0;
    int checkIdx = 0;
    for (int s = 0; s < segmentCount; s++) {
      // Base data blocks for this segment, accounting for "deduct last N segments by 1" rule.
      int baseDataPerSeg =
          blocksPerSegment - (s >= (segmentCount - Math.max(0, deductBlocksFromSegments)) ? 1 : 0);
      // In cross-segment mode, each segment also carries crossCheckBlocks additional data-like
      // blocks
      // that participate in segment-level decode. Include them in the data-per-segment target.
      int nominalDps = baseDataPerSeg + Math.max(0, crossCheckBlocks);
      int remainingData = splitfileDataKeys != null ? (splitfileDataKeys.length - dataIdx) : 0;
      int dps = Math.clamp(remainingData, 0, nominalDps);
      int remainingCheck = splitfileCheckKeys != null ? (splitfileCheckKeys.length - checkIdx) : 0;
      int cps = Math.clamp(remainingCheck, 0, checkBlocksPerSegment);
      SplitFileSegmentKeys seg =
          new SplitFileSegmentKeys(
              dps, cps, splitfileSingleCryptoKey, splitfileSingleCryptoAlgorithm);
      for (int i = 0; i < dps && dataIdx < splitfileDataKeys.length; i++) {
        seg.setKey(i, splitfileDataKeys[dataIdx++]);
      }
      for (int i = 0; i < cps && checkIdx < splitfileCheckKeys.length; i++) {
        seg.setKey(dps + i, splitfileCheckKeys[checkIdx++]);
      }
      segs[s] = seg;
    }
    this.segments = segs;
  }

  private void writeSimpleManifestSection(DataOutputStream dos)
      throws IOException, MetadataUnresolvedException {
    if (documentType != DocumentType.SIMPLE_MANIFEST) return;
    dos.writeInt(manifestEntries.size());
    LinkedList<Metadata> unresolvedMetadata = new LinkedList<>();
    for (Map.Entry<String, Metadata> entry : manifestEntries.entrySet()) {
      String name = entry.getKey();
      byte[] nameData = name.getBytes(StandardCharsets.UTF_8);
      if (nameData.length > Short.MAX_VALUE)
        throw new IllegalArgumentException("Manifest name too long");
      dos.writeShort(nameData.length);
      dos.write(nameData);
      Metadata meta = entry.getValue();
      ManifestEntryData med = buildManifestEntryPayload(meta, unresolvedMetadata);
      dos.writeShort(med.data.length);
      if (med.data.length > 0) dos.write(med.data);
    }
    if (!unresolvedMetadata.isEmpty()) {
      Metadata[] meta = unresolvedMetadata.toArray(new Metadata[0]);
      throw new MetadataUnresolvedException(meta, "Manifest data too long and not resolved");
    }
  }

  private static final class ManifestEntryData {
    final byte[] data;

    ManifestEntryData(byte[] data) {
      this.data = data;
    }
  }

  private ManifestEntryData buildManifestEntryPayload(
      Metadata meta, LinkedList<Metadata> unresolvedMetadata) {
    try {
      byte[] data = meta.writeToByteArray();
      if (data.length > MAX_SIZE_IN_MANIFEST) {
        FreenetURI uri = meta.resolvedURI;
        String n = meta.resolvedName;
        if (uri != null) {
          Metadata redirect = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, uri, null);
          data = redirect.writeToByteArray();
        } else if (n != null) {
          Metadata redirect = new Metadata(DocumentType.ARCHIVE_METADATA_REDIRECT, n);
          data = redirect.writeToByteArray();
        } else {
          unresolvedMetadata.addLast(meta);
          return new ManifestEntryData(new byte[0]);
        }
      }
      return new ManifestEntryData(data);
    } catch (MetadataUnresolvedException e) {
      for (Metadata m : e.mustResolve) unresolvedMetadata.addFirst(m);
      return new ManifestEntryData(new byte[0]);
    }
  }

  private void writeTailRedirectSection(DataOutputStream dos) throws IOException {
    if ((documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        || (documentType == DocumentType.ARCHIVE_METADATA_REDIRECT)
        || (documentType == DocumentType.SYMBOLIC_SHORTLINK)) {
      byte[] data = targetName.getBytes(StandardCharsets.UTF_8);
      if (data.length > Short.MAX_VALUE)
        throw new IllegalArgumentException("Archive internal redirect name too long");
      dos.writeShort(data.length);
      dos.write(data);
    }
  }

  /** have this metadata flags? */
  public boolean haveFlags() {
    return ((documentType == DocumentType.SIMPLE_REDIRECT)
        || (documentType == DocumentType.MULTI_LEVEL_METADATA)
        || (documentType == DocumentType.ARCHIVE_MANIFEST)
        || (documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        || (documentType == DocumentType.ARCHIVE_METADATA_REDIRECT)
        || (documentType == DocumentType.SYMBOLIC_SHORTLINK));
  }

  /** Get the splitfile type. */
  public SplitfileAlgorithm getSplitfileType() {
    return splitfileAlgorithm;
  }

  @SuppressWarnings("unused")
  public ClientCHK[] getSplitfileDataKeys() {
    return splitfileDataKeys;
  }

  @SuppressWarnings("unused")
  public ClientCHK[] getSplitfileCheckKeys() {
    return splitfileCheckKeys;
  }

  public boolean isCompressed() {
    return compressionCodec != null;
  }

  public COMPRESSOR_TYPE getCompressionCodec() {
    return compressionCodec;
  }

  public long dataLength() {
    return dataLength;
  }

  public byte[] splitfileParams() {
    return splitfileParams;
  }

  public long uncompressedDataLength() {
    return this.decompressedLength;
  }

  @SuppressWarnings("unused")
  public FreenetURI getResolvedURI() {
    return resolvedURI;
  }

  public void resolve(FreenetURI uri) {
    this.resolvedURI = uri;
  }

  public void resolve(String name) {
    this.resolvedName = name;
  }

  public RandomAccessBucket toBucket(BucketFactory bf)
      throws MetadataUnresolvedException, IOException {
    RandomAccessBucket b = bf.makeBucket(-1);
    try (DataOutputStream dos = new DataOutputStream(b.getOutputStream())) {
      writeTo(dos);
      dos.flush(); // Ensure data is written before setReadOnly()
    } catch (IOException e) {
      b.free();
      throw e;
    }
    b.setReadOnly(); // Must be after dos.close()
    return b;
  }

  public boolean isResolved() {
    return (resolvedURI != null) || (resolvedName != null);
  }

  public void setArchiveManifest() {
    archiveType = ARCHIVE_TYPE.getArchiveType(clientMetadata.getMIMEType());
    clientMetadata.clear();
    documentType = DocumentType.ARCHIVE_MANIFEST;
  }

  public String getMIMEType() {
    if (clientMetadata == null) return null;
    return clientMetadata.getMIMEType();
  }

  @SuppressWarnings("unused")
  public void clearSplitfileKeys() {
    splitfileDataKeys = null;
    splitfileCheckKeys = null;
    segments = null;
  }

  public int countDocuments() {
    return manifestEntries.size();
  }

  /**
   * Helper for composing manifests<br>
   * It is a replacement for mkRedirectionManifestWithMetadata, used in BaseManifestPutter
   *
   * <PRE>
   * Metadata item = &lt;Redirect to a html&gt;
   * SimpleManifestComposer smc = new SimpleManifestComposer();
   * smc.add("index.html", item);
   * smc.add("", item);  // make it the default item
   * SimpleManifestComposer subsmc = new SimpleManifestComposer();
   * subsmc.add("content.txt", item2);
   * smc.add("data", subsmc.getMetadata();
   * Metadata manifest = smc.getMetadata();
   * // manifest contains now a structure like returned from mkRedirectionManifestWithMetadata
   * </PRE>
   *
   * @see BaseManifestPutter
   */
  public static class SimpleManifestComposer {

    private Metadata m;

    /** Create a new compose helper (an empty dir) */
    public SimpleManifestComposer() {
      m = new Metadata();
      m.documentType = DocumentType.SIMPLE_MANIFEST;
      m.noMIME = true;
      m.manifestEntries = new HashMap<>();
    }

    /**
     * Add an item to the manifest
     *
     * @param name the item name
     * @param item
     */
    public void addItem(String name, Metadata item) {
      if (name == null || item == null) throw new NullPointerException();
      if (m == null) throw new IllegalStateException("You can't call it after getMetadata()");
      if (m.manifestEntries.containsKey(name))
        throw new IllegalStateException("You can't add a item twice: '" + name + "'");
      m.manifestEntries.put(name, item);
    }

    /**
     * stop editing and return the metadata object
     *
     * @return the composed metadata object
     */
    public Metadata getMetadata() {
      // after handing off the metadata object it is read only.
      Metadata result = m;
      m = null;
      return result;
    }
  }

  public String dump() {
    StringBuilder sb = new StringBuilder();
    dump(0, sb);
    return sb.toString();
  }

  public void dump(int indent, StringBuilder sb) {
    dumpline(indent, sb, "");
    dumpline(indent, sb, "Document type: " + documentType);
    dumpline(
        indent,
        sb,
        "Flags: sf="
            + splitfile
            + " dbr="
            + dbr
            + " noMIME="
            + noMIME
            + " cmime="
            + compressedMIME
            + " extra="
            + extraMetadata
            + " fullkeys="
            + fullKeys);
    if (archiveType != null) dumpline(indent, sb, "Archive type: " + archiveType);
    if (compressionCodec != null) dumpline(indent, sb, "Compression codec: " + compressionCodec);
    if (simpleRedirectKey != null) dumpline(indent, sb, "Simple redirect: " + simpleRedirectKey);
    if (splitfile) {
      dumpline(indent, sb, "Splitfile algorithm: " + splitfileAlgorithm);
      dumpline(indent, sb, "Splitfile blocks: " + splitfileBlocks);
      dumpline(indent, sb, "Splitfile blocks: " + splitfileCheckBlocks);
    }
    if (targetName != null) dumpline(indent, sb, "Target name: " + targetName);

    if (manifestEntries != null) {
      for (Map.Entry<String, Metadata> entry : manifestEntries.entrySet()) {
        dumpline(indent, sb, "Entry: " + entry.getKey() + ":");
        entry.getValue().dump(indent + 1, sb);
      }
    }
  }

  private void dumpline(int indent, StringBuilder sb, String string) {
    sb.append(" ".repeat(Math.max(0, indent)));
    sb.append(string);
    sb.append("\n");
  }

  /**
   * Returns a mutable {@code Map<String, Object>} view of the given object.
   *
   * <p>Behavior: - If {@code o} is already a {@code HashMap<?, ?>}, it returns the same instance
   * with a localized, justified unchecked cast. - If {@code o} is a {@code Map<?, ?>} but not a
   * {@code HashMap}, it creates a new {@code HashMap<String, Object>} and copies entries after
   * verifying keys are {@code String}. - Otherwise it throws {@link ClassCastException}.
   *
   * <p>Rationale: Some builder paths store subdirectories as {@code HashMap<String,Object>} and
   * mutate them in-place. We centralize the only unavoidable unchecked cast here, backed by runtime
   * checks when the source is not a {@code HashMap}.
   */
  public static Map<String, Object> forceMap(Object o) {
    if (o instanceof HashMap<?, ?> raw) {
      return uncheckedCast(raw);
    }
    if (o instanceof Map<?, ?> m) {
      HashMap<String, Object> typed = new HashMap<>();
      for (Map.Entry<?, ?> e : m.entrySet()) {
        Object k = e.getKey();
        if (!(k instanceof String)) {
          throw new ClassCastException(
              "Expected String keys in map, got " + (k == null ? "null" : k.getClass().getName()));
        }
        typed.put((String) k, e.getValue());
      }
      return typed;
    }
    throw new ClassCastException(
        "Expected Map, got " + (o == null ? "null" : o.getClass().getName()));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> uncheckedCast(HashMap<?, ?> raw) {
    // Safe by construction in our code paths: subdirectory maps are created as
    // HashMap<String,Object>.
    return (HashMap<String, Object>) raw;
  }

  public short getParsedVersion() {
    return parsedVersion;
  }

  public boolean hasTopData() {
    return topSize != 0 || topCompressedSize != 0 || topBlocksRequired != 0 || topBlocksTotal != 0;
  }

  public HashResult[] getHashes() {
    return hashes;
  }

  /** If there is a custom (not computed from hashes) splitfile key, return it. Else return null. */
  public byte[] getCustomSplitfileKey() {
    if (specifySplitfileKey) return splitfileSingleCryptoKey;
    return new byte[0];
  }

  public byte[] getSplitfileCryptoKey() {
    return splitfileSingleCryptoKey;
  }

  public byte[] getHashThisLayerOnly() {
    return hashThisLayerOnly;
  }

  public byte getSplitfileCryptoAlgorithm() {
    return splitfileSingleCryptoAlgorithm;
  }

  public CompatibilityMode getTopCompatibilityMode() {
    return topCompatibilityMode;
  }

  public boolean getTopDontCompress() {
    return topDontCompress;
  }

  public short getTopCompatibilityCode() {
    return topCompatibilityMode.code;
  }

  public CompatibilityMode getMinCompatMode() {
    return minCompatMode;
  }

  public CompatibilityMode getMaxCompatMode() {
    return maxCompatMode;
  }

  public int getCrossCheckBlocks() {
    return crossCheckBlocks;
  }

  public int getCheckBlocksPerSegment() {
    return checkBlocksPerSegment;
  }

  public int getDataBlocksPerSegment() {
    return blocksPerSegment;
  }

  public int getSegmentCount() {
    return segmentCount;
  }

  // Note: legacy behavior retained for compatibility; segments are cleared after being grabbed to
  // reduce memory usage.
  @SuppressWarnings("unused")
  public SplitFileSegmentKeys[] grabSegmentKeys() throws FetchException {
    synchronized (this) {
      if (segments == null && splitfileDataKeys != null && splitfileCheckKeys != null)
        throw new FetchException(
            FetchExceptionMode.INTERNAL_ERROR,
            "Please restart the download, need to re-parse metadata due to internal changes");
      SplitFileSegmentKeys[] segs = segments;
      segments = null;
      return segs;
    }
  }

  public SplitFileSegmentKeys[] getSegmentKeys() throws FetchException {
    synchronized (this) {
      if (segments == null && splitfileDataKeys != null && splitfileCheckKeys != null)
        throw new FetchException(
            FetchExceptionMode.INTERNAL_ERROR,
            "Please restart the download, need to re-parse metadata due to internal changes");
      return segments;
    }
  }

  public int getDeductBlocksFromSegments() {
    return deductBlocksFromSegments;
  }

  /**
   * Return a best-guess compatibility mode, guaranteed not to be COMPAT_UNKNOWN or COMPAT_CURRENT.
   */
  public CompatibilityMode guessCompatibilityMode() {
    CompatibilityMode mode = getTopCompatibilityMode();
    if (mode != CompatibilityMode.COMPAT_UNKNOWN) return mode;
    CompatibilityMode min = minCompatMode;
    CompatibilityMode max = maxCompatMode;
    if (max == CompatibilityMode.COMPAT_CURRENT) max = CompatibilityMode.latest();
    if (min == max) return min;
    if (min == CompatibilityMode.COMPAT_UNKNOWN) return max;
    if (max == CompatibilityMode.COMPAT_UNKNOWN) return min;
    return max;
  }

  public static boolean isValidSplitfileCryptoAlgorithm(byte cryptoAlgorithm) {
    return cryptoAlgorithm == 0 || Key.isValidCryptoAlgorithm(cryptoAlgorithm);
  }
}

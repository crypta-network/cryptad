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

/**
 * Metadata represents the structured, serialized description of content stored or fetched by the
 * Crypta node. It can describe simple redirects, manifests (directory‐like structures), archives
 * and splitfiles (content composed of many CHK blocks with optional FEC). Instances are created
 * when parsing on‑disk or network representations, or constructed by client code before
 * serialization.
 *
 * <p>Typical usage follows a parse → inspect → act pattern during fetches, and a build → serialize
 * → insert pattern during inserts. The class exposes helpers to read the header, manifest entries,
 * and splitfile layout, while keeping low‑level binary details encapsulated. After parsing, some
 * derived fields (for example segment counts) are computed from the serialized parameters to match
 * the historical format expected by fetchers.
 *
 * <p>Thread-safety and mutability: a {@code Metadata} instance is mutable during construction and
 * parsing. Once populated it is commonly treated as effectively immutable by callers. No internal
 * synchronization is provided; publish safely if sharing across threads or prefer per‑thread
 * instances. Larger structures (such as segment keys) may be shared read‑most after construction.
 *
 * <ul>
 *   <li>Parses and writes versioned metadata with backwards‑compatible layout rules.
 *   <li>Represents manifests and redirect entries using maps and {@link Metadata} children.
 *   <li>Supports splitfiles including per‑segment and cross‑segment redundancy.
 * </ul>
 *
 * @see #construct(byte[])
 * @see #construct(network.crypta.support.api.Bucket)
 * @see network.crypta.client.async.SplitFileSegmentKeys
 * @see network.crypta.keys.ClientCHK
 */
public class Metadata implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(Metadata.class);

  @Serial private static final long serialVersionUID = 1L;
  static final long FREENET_METADATA_MAGIC = 0xf053b2842d91482bL;
  static final int MAX_SPLITFILE_PARAMS_LENGTH = 32768;

  /** Soft limit, to avoid memory DoS */
  static final int MAX_SPLITFILE_BLOCKS = 1000 * 1000;

  /** Splitfile parameters: segmenting without any special deductions. */
  public static final short SPLITFILE_PARAMS_SIMPLE_SEGMENT = 0;

  /** Splitfile parameters: last {@code N} segments lose one data block for balancing. */
  public static final short SPLITFILE_PARAMS_SEGMENT_DEDUCT_BLOCKS = 1;

  /** Splitfile parameters: include cross‑segment parity blocks for large files. */
  public static final short SPLITFILE_PARAMS_CROSS_SEGMENT = 2;

  /** URI at which this metadata has been or will be inserted/resolved. */
  FreenetURI resolvedURI;

  /** Name at which this metadata has been or will be stored inside a container. */
  String resolvedName;

  // Actual parsed data

  /** Active document type for this metadata instance. */
  DocumentType documentType;

  /**
   * Identifies the high‑level kind of document represented by this metadata, such as a simple
   * redirect, a manifest (directory), or archival/redirect variants.
   */
  public enum DocumentType {
    /** Simple redirect to a single target URI. */
    SIMPLE_REDIRECT((byte) 0),
    /** Indirection layer pointing to another metadata block. */
    MULTI_LEVEL_METADATA((byte) 1),
    /** Directory‑like map of names to files/sub‑manifests. */
    SIMPLE_MANIFEST((byte) 2),
    /** Archive manifest describing packaged content. */
    ARCHIVE_MANIFEST((byte) 3),
    /** Redirect to a path inside an archive. */
    ARCHIVE_INTERNAL_REDIRECT((byte) 4),
    /** Redirect to metadata stored inside an archive. */
    ARCHIVE_METADATA_REDIRECT((byte) 5),
    /** Human‑readable shortlink to a target name. */
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
    } catch (IllegalArgumentException _) {
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
    } catch (IllegalArgumentException _) {
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

  /** Parsed metadata version number (0 = legacy, 1 = current). */
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
  // required in the future, consider reassigning this placeholder.
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

  /** Whether {@link #compressedMIMEParams} is present and valid. */
  boolean hasCompressedMIMEParams;

  /** Compressed MIME parameter value when {@link #hasCompressedMIMEParams} is true. */
  short compressedMIMEParams;

  /** The simple redirect key */
  FreenetURI simpleRedirectKey;

  /**
   * Metadata is sometimes used as a key in hashtables. Therefore, it needs a persistent hashCode.
   */
  private final int hashCode;

  /** Splitfile algorithm in use for this document when {@link #splitfile} is true. */
  SplitfileAlgorithm splitfileAlgorithm;

  /** Specifies the splitfile layout algorithm used for data and parity blocks. */
  public enum SplitfileAlgorithm {
    /** No redundancy; data only. */
    NONREDUNDANT((short) 0),
    /** Standard layout with forward‑error correction. */
    ONION_STANDARD((short) 1);

    /** Numeric identifier for the algorithm as serialized on disk. */
    public final short code;

    SplitfileAlgorithm(short code) {
      this.code = code;
    }

    /**
     * Returns the algorithm enum for the given serialized code.
     *
     * @param s numeric code as stored in metadata.
     * @return the matching {@link SplitfileAlgorithm}.
     * @throws IllegalArgumentException if the code is out of range.
     */
    public static SplitfileAlgorithm getByCode(short s) {
      if (s < 0 || s >= values().length) throw new IllegalArgumentException("Bad splitfile code");
      return values()[s];
    }
  }

  /**
   * Maximum payload size, in bytes, for values stored directly in a manifest entry. Larger values
   * must be referenced indirectly.
   */
  public static final int MAX_SIZE_IN_MANIFEST = Short.MAX_VALUE;

  /** Raw splitfile parameters blob as serialized in metadata. */
  byte[] splitfileParams;

  /** Total data blocks across the entire splitfile (includes cross‑segment blocks). */
  int splitfileBlocks;

  /** Total parity/check blocks across the entire splitfile. */
  int splitfileCheckBlocks;

  /** Per‑block client keys for data blocks; populated when keys are present. */
  ClientCHK[] splitfileDataKeys;

  /** Per‑block client keys for parity/check blocks; populated when keys are present. */
  ClientCHK[] splitfileCheckKeys;

  /** Used if splitfile single crypto key is enabled */
  byte splitfileSingleCryptoAlgorithm;

  /** Common crypto key applied to all blocks when parsed version ≥ 1; otherwise {@code null}. */
  byte[] splitfileSingleCryptoKey;

  /** If false, the splitfile key can be computed from hashes; if true, it must be specified. */
  private boolean specifySplitfileKey;

  /** Hash of this layer only (not final data); optional and may be {@code null}. */
  byte[] hashThisLayerOnly;

  /** Nominal number of data blocks per segment (excludes cross‑segment blocks). */
  int blocksPerSegment;

  /** Number of parity/check blocks per segment. */
  int checkBlocksPerSegment;

  /** Number of segments computed from the layout parameters. */
  int segmentCount;

  /** How many trailing segments lose one data block for balancing. */
  int deductBlocksFromSegments;

  /** Number of cross‑segment parity blocks per segment (0 when not used). */
  int crossCheckBlocks;

  /** Per‑segment key lists; may be {@code null} until built. */
  SplitFileSegmentKeys[] segments;

  /** Minimum compatibility mode inferred for this metadata. */
  CompatibilityMode minCompatMode = CompatibilityMode.COMPAT_UNKNOWN;

  /** Maximum compatibility mode inferred for this metadata. */
  CompatibilityMode maxCompatMode = CompatibilityMode.COMPAT_UNKNOWN;

  // Manifests
  /** Manifest entries by name */
  HashMap<String, Metadata> manifestEntries;

  /** Archive internal redirect: name of file in archive SympolicShortLink: Target name */
  String targetName;

  /** Client metadata such as MIME type; may be {@code null}. */
  ClientMetadata clientMetadata;

  /** Array of hashes (final/original data), or {@code null} when not provided. */
  private HashResult[] hashes;

  /** Top-level logical data size in bytes for progress reporting. */
  public final long topSize;

  /** Top-level compressed size in bytes when compression applies; else equals {@link #topSize}. */
  public final long topCompressedSize;

  /** Blocks required at the top level to decode the referenced content. */
  public final int topBlocksRequired;

  /** Total blocks at the top level for the referenced content. */
  public final int topBlocksTotal;

  /** Whether top-level compression is disabled for the referenced content. */
  public final boolean topDontCompress;

  /** Declared compatibility mode for the top layer of this metadata. */
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
      for (int i = 0; i < this.hashes.length; i++) {
        this.hashes[i] = new HashResult(orig.hashes[i]);
      }
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
   * Parse a block of bytes into a {@code Metadata} instance from an in‑memory byte array.
   *
   * <p>The method validates the header and contents and constructs a fully populated {@code
   * Metadata}. The input array is not retained by the returned object.
   *
   * @param data the serialized metadata bytes; the method reads the entire array and does not
   *     modify it; must not be {@code null}.
   * @return a parsed {@code Metadata} instance representing the provided bytes; never {@code null}
   *     when parsing succeeds.
   * @throws MetadataParseException if the data is malformed, unsupported for the current parser
   *     version, or otherwise fails structural validation.
   */
  public static Metadata construct(byte[] data) throws MetadataParseException {
    try {
      return new Metadata(data);
    } catch (IOException e) {
      throw (MetadataParseException) new MetadataParseException("Caught " + e).initCause(e);
    }
  }

  /**
   * Parse a bucket of data into a {@code Metadata} instance.
   *
   * <p>The bucket is read sequentially; callers remain responsible for its lifecycle. The returned
   * instance does not retain a reference to the bucket.
   *
   * @param data source {@link Bucket} providing the serialized metadata; must be readable for at
   *     least {@link Bucket#size()} bytes.
   * @return a parsed {@code Metadata} instance representing the stream contents.
   * @throws MetadataParseException if the serialized form is invalid or unsupported.
   * @throws IOException if an I/O error occurs while reading from the bucket.
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
   * @throws IOException if the data is incomplete or an I/O error occurs while reading from the
   *     in‑memory stream.
   * @throws MetadataParseException if the serialized bytes are malformed or unsupported for the
   *     current parser version.
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
   * Parse metadata from a {@link DataInputStream} with a known remaining length.
   *
   * <p>The stream is read according to the on‑wire format: header and flags, optional top‑level
   * fields, followed by manifest or splitfile sections. The constructor does not close the supplied
   * stream.
   *
   * @param dis input stream positioned at the beginning of a serialized metadata structure; not
   *     closed by this method; must not be {@code null}.
   * @param length total number of bytes available for the metadata payload from {@code dis}; used
   *     for bounds checking and manifest parsing decisions.
   * @throws IOException if an I/O error occurs or the stream cannot supply the required bytes.
   * @throws MetadataParseException if the payload is structurally invalid or uses an unsupported
   *     version or document type.
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

  /**
   * Derives the splitfile crypto key from the provided hashes. Requires an SHA‑256 result.
   *
   * @param hashes array of {@link HashResult}; must contain an SHA‑256 entry; must not be {@code
   *     null} or empty.
   * @return a 32‑byte key derived from the SHA‑256 of the final data.
   * @throws IllegalArgumentException if {@code hashes} is missing an SHA‑256 entry.
   */
  public static byte[] getCryptoKey(HashResult[] hashes) {
    if (hashes == null || hashes.length == 0 || !HashResult.contains(hashes, HashType.SHA256))
      throw new IllegalArgumentException(
          "No hashes in getCryptoKey - need hashes to generate splitfile key!");
    byte[] hash = HashResult.get(hashes, HashType.SHA256);
    return getCryptoKey(hash);
  }

  /**
   * Derives the splitfile crypto key directly from an SHA‑256 hash value.
   *
   * @param hash a 32‑byte SHA‑256 of the final data; must not be {@code null}.
   * @return a 32‑byte key bytes array suitable for splitfile encryption.
   */
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

  /**
   * Computes the seed used for cross‑segment parity generation from final‑data hashes and the
   * optional hash of this layer only.
   *
   * @param hashes array of hashes of the final/original data (must include SHA‑256); used as
   *     primary input.
   * @param hashThisLayerOnly optional hash of this layer’s data (may be {@code null}); incorporated
   *     for added uniqueness.
   * @return seed bytes for cross‑segment parity; never {@code null} when inputs are valid.
   */
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

  /**
   * Computes the cross‑segment parity seed from a single hash value (typically SHA‑256).
   *
   * @param hash a 32‑byte hash value; must not be {@code null}.
   * @return seed bytes for cross‑segment parity; never {@code null}.
   */
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
   * @param dir a map from entry names to either strings (external redirects) or nested maps (child
   *     directories). Entry names must be simple names without slashes.
   * @return a new {@code Metadata} instance containing a simple redirect manifest populated from
   *     the provided map.
   * @throws MalformedURLException if a provided redirect string cannot be parsed as a valid {@link
   *     FreenetURI}.
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
   *
   * @param dir a map from entry names to either {@link Metadata} (files/redirects) or nested maps
   *     (sub‑directories). Names must not contain {@code '/'}.
   * @return a new {@code Metadata} instance whose manifest contains the provided entries.
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
   * @param docType the document type; must be a kind that accepts a single argument (currently
   *     {@link DocumentType#ARCHIVE_INTERNAL_REDIRECT} or {@link DocumentType#SYMBOLIC_SHORTLINK}).
   * @param archiveType archive flavor when relevant (only used by archive‑related document types);
   *     may be {@code null} for non‑archive types.
   * @param compressionCodec compression codec associated with the content when applicable; may be
   *     {@code null} when no compression applies.
   * @param arg argument for the document type; for {@code ARCHIVE_INTERNAL_REDIRECT}, the path
   *     inside the archive to read.
   * @param cm optional client metadata (e.g., MIME type); may be {@code null} to use defaults.
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

  /**
   * Convenience constructor for redirect‑like documents that do not require top‑layer size/blocks
   * details.
   *
   * @param docType the document type (redirect or archive‑related).
   * @param archiveType archive flavor when relevant; {@code null} when not applicable.
   * @param compressionCodec compression codec for archive payloads when relevant; {@code null} when
   *     not applicable.
   * @param uri target {@link FreenetURI} referenced by this entry.
   * @param cm client metadata describing MIME type and related properties; may be {@code null}.
   */
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
   * @param docType the document type (redirect or archive‑related).
   * @param archiveType archive flavor when relevant; {@code null} when not applicable.
   * @param compressionCodec compression codec for archive payloads when relevant; {@code null} when
   *     not applicable.
   * @param uri target {@link FreenetURI} referenced by this entry; must be a valid CHK for
   *     splitfile payloads when full keys are not used.
   * @param cm client metadata describing MIME type and related properties; may be {@code null}.
   * @param origDataLength original (uncompressed) data length in bytes; non‑negative.
   * @param origCompressedDataLength compressed data length in bytes when compression is used;
   *     otherwise typically equals {@code origDataLength}.
   * @param reqBlocks number of blocks required to decode at the top layer; non‑negative.
   * @param totalBlocks total number of blocks at the top layer; non‑negative and ≥ {@code
   *     reqBlocks}.
   * @param topDontCompress whether top‑layer compression is disabled for the referenced payload.
   * @param topCompatibilityMode declared top compatibility mode; must not be {@link
   *     InsertContext.CompatibilityMode#COMPAT_CURRENT}.
   * @param hashes optional array of hashes (e.g., SHA‑256) of the final data; may be {@code null}
   *     or non‑empty.
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
   *     of metadata. This usually happens for huge splitfiles, which can be a pyramid of one block
   *     with metadata for a splitfile full of metadata, that metadata then encodes another
   *     splitfile full of metadata, etc. Hence, we can support very large files.
   * @param hashes Various hashes of <b>the final data</b>. There should always be at least an
   *     SHA256 hash, unless we are inserting with an old compatibility mode.
   * @param hashThisLayerOnly Hash of the data in this layer (before compression). Separate from
   *     hashes of the final data. Not currently verified.
   * @param origDataSize The size of the final/original data.
   * @param origCompressedDataSize The size of the final/original data after it was compressed.
   * @param requiredBlocks The number of blocks required on fetch to reconstruct the final data.
   *     Hence, as soon as we have the top splitfile metadata (i.e. hopefully in the top block), we
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
   * @return a newly allocated byte array containing the serialized representation of this metadata;
   *     never {@code null}.
   * @throws MetadataUnresolvedException if the instance still references unresolved sub‑metadata at
   *     the time of serialization (for example, missing manifest entries required by the format).
   *     Callers should resolve or remove such references before invoking this method.
   * @throws java.io.UncheckedIOException if an unexpected I/O error occurs while writing to the
   *     in‑memory buffer.
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

  /**
   * Computes the number of bytes that would be written by {@link #writeTo(DataOutputStream)}
   * without allocating an intermediate buffer.
   *
   * @return total serialized length in bytes.
   * @throws MetadataUnresolvedException if unresolved child metadata prevents serialization.
   * @throws java.io.UncheckedIOException if an I/O error occurs while counting bytes.
   */
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
   * @throws IOException if the stream cannot supply enough bytes for a full key or an I/O error
   *     occurs while reading.
   * @throws MalformedURLException If the key could not be read due to an error in parsing the key.
   *     REDFLAG: May want to recover from these in the future, hence the short length.
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
   * @throws IOException if the destination stream rejects bytes or another I/O error occurs while
   *     writing.
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

  /**
   * Indicates whether this instance represents a simple manifest document.
   *
   * @return {@code true} when {@link DocumentType#SIMPLE_MANIFEST} is the active document type;
   *     {@code false} otherwise.
   */
  public boolean isSimpleManifest() {
    return documentType == DocumentType.SIMPLE_MANIFEST;
  }

  /**
   * Get the sub-document in a manifest file with the given name.
   *
   * @param name the child entry name to lookup within the current manifest; must be a simple name
   *     without slashes.
   * @return the {@code Metadata} document associated with {@code name}, or {@code null} when no
   *     such entry exists.
   */
  public Metadata getDocument(String name) {
    return manifestEntries.get(name);
  }

  /**
   * Return and remove a specific document. Used in persistent requests so that when removeFrom() is
   * called, the default document won't be removed, since it is being processed.
   *
   * @param name the child entry name to remove from the manifest; must not contain path separators.
   * @return the removed {@code Metadata} document if present, or {@code null} if the entry did not
   *     exist.
   */
  public Metadata grabDocument(String name) {
    return manifestEntries.remove(name);
  }

  /**
   * The default document is the one which has an empty name.
   *
   * @return the {@code Metadata} document mapped to the empty name within this manifest, or {@code
   *     null} when no default is set.
   */
  public Metadata getDefaultDocument() {
    return getDocument("");
  }

  /**
   * Return and remove the default document. Used in persistent requests so that when removeFrom()
   * is called, the default document won't be removed, since it is being processed.
   *
   * @return the removed default {@code Metadata} document, or {@code null} when none was present.
   */
  public Metadata grabDefaultDocument() {
    return grabDocument("");
  }

  /**
   * Get all documents in the manifest (ignores default doc).
   *
   * @return a mapping from non‑default entry names to their corresponding {@code Metadata}
   *     documents; the returned map is a shallow copy and modifications do not affect this
   *     instance.
   */
  public Map<String, Metadata> getDocuments() {
    HashMap<String, Metadata> docs = new HashMap<>();
    for (Map.Entry<String, Metadata> entry : manifestEntries.entrySet()) {
      String st = entry.getKey();
      if (!st.isEmpty()) docs.put(st, entry.getValue());
    }
    return docs;
  }

  /**
   * Indicates whether this metadata points to a single target URI rather than a directory tree.
   *
   * @return {@code true} for simple redirect, multi‑level metadata, or archive manifest types;
   *     {@code false} otherwise.
   */
  public boolean isSingleFileRedirect() {
    return ((!splitfile)
        && ((documentType == DocumentType.SIMPLE_REDIRECT)
            || (documentType == DocumentType.MULTI_LEVEL_METADATA)
            || (documentType == DocumentType.ARCHIVE_MANIFEST)));
  }

  /**
   * Returns the single target {@link FreenetURI} when this instance represents a redirect‑like
   * document.
   *
   * @return the target URI for redirect‑like types, or {@code null} when not applicable.
   */
  public FreenetURI getSingleTarget() {
    return simpleRedirectKey;
  }

  /**
   * Indicates whether this instance represents an archive manifest.
   *
   * @return {@code true} when {@link DocumentType#ARCHIVE_MANIFEST} is active; {@code false}
   *     otherwise.
   */
  public boolean isArchiveManifest() {
    return documentType == DocumentType.ARCHIVE_MANIFEST;
  }

  /**
   * Is this an archive internal metadata redirect?
   *
   * @return {@code true} when {@link DocumentType#ARCHIVE_METADATA_REDIRECT} is active; {@code
   *     false} otherwise.
   */
  public boolean isArchiveMetadataRedirect() {
    return documentType == DocumentType.ARCHIVE_METADATA_REDIRECT;
  }

  /**
   * Is this an Archive internal redirect?
   *
   * @return {@code true} when {@link DocumentType#ARCHIVE_INTERNAL_REDIRECT} is active; {@code
   *     false} otherwise.
   */
  public boolean isArchiveInternalRedirect() {
    return documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT;
  }

  /**
   * Returns the name of the document referred to inside the archive when this is an
   * archive‑internal redirect.
   *
   * @return the internal path name for archive redirects; throws {@link IllegalArgumentException}
   *     for non‑archive redirects.
   */
  public String getArchiveInternalName() {
    if ((documentType != DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        && (documentType != DocumentType.ARCHIVE_METADATA_REDIRECT))
      throw new IllegalArgumentException();
    return targetName;
  }

  /**
   * Returns the name of the document referred to when this instance is a symbolic shortlink.
   *
   * @return the target name for {@link DocumentType#SYMBOLIC_SHORTLINK}; throws {@link
   *     IllegalArgumentException} otherwise.
   */
  public String getSymbolicShortlinkTargetName() {
    if (documentType != DocumentType.SYMBOLIC_SHORTLINK) throw new IllegalArgumentException();
    return targetName;
  }

  /**
   * Returns the client metadata associated with this document, including MIME type information.
   *
   * @return the client metadata instance; may be {@code null} if not provided.
   */
  public ClientMetadata getClientMetadata() {
    return clientMetadata;
  }

  /**
   * Indicates whether this document is a splitfile.
   *
   * @return {@code true} when the splitfile flag is set; {@code false} otherwise.
   */
  public boolean isSplitfile() {
    return splitfile;
  }

  /**
   * Indicates whether this document is a simple splitfile (non‑manifest redirect).
   *
   * @return {@code true} for simple redirect splitfiles; {@code false} otherwise.
   */
  @SuppressWarnings("unused")
  public boolean isSimpleSplitfile() {
    return splitfile && (documentType == DocumentType.SIMPLE_REDIRECT);
  }

  /**
   * Indicates whether this document is multi‑level/indirect metadata.
   *
   * @return {@code true} when {@link DocumentType#MULTI_LEVEL_METADATA} is active; {@code false}
   *     otherwise.
   */
  public boolean isMultiLevelMetadata() {
    return documentType == DocumentType.MULTI_LEVEL_METADATA;
  }

  /**
   * Returns the archive type, when applicable.
   *
   * @return the archive type for archive‑related documents; may be {@code null} when not
   *     applicable.
   */
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

  /**
   * Indicates whether this document is a simple redirect (KeyExplorer helper).
   *
   * @return {@code true} when {@link DocumentType#SIMPLE_REDIRECT} is active; {@code false}
   *     otherwise.
   */
  public boolean isSimpleRedirect() {
    return documentType == DocumentType.SIMPLE_REDIRECT;
  }

  /**
   * Indicates whether the {@code noMIME} flag is enabled (KeyExplorer helper).
   *
   * @return {@code true} when MIME is intentionally omitted; {@code false} otherwise.
   */
  @SuppressWarnings("unused")
  public boolean isNoMimeEnabled() {
    return noMIME;
  }

  /**
   * Returns the resolved metadata name (e.g., {@code .metadata-N}) used by KeyExplorer.
   *
   * @return the resolved name string; may be {@code null} if not assigned.
   */
  @SuppressWarnings("unused")
  public String getResolvedName() {
    return resolvedName;
  }

  /**
   * Indicates whether this document is a symbolic shortlink.
   *
   * @return {@code true} when {@link DocumentType#SYMBOLIC_SHORTLINK} is active; {@code false}
   *     otherwise.
   */
  public boolean isSymbolicShortlink() {
    return documentType == DocumentType.SYMBOLIC_SHORTLINK;
  }

  /**
   * Write the metadata as binary.
   *
   * @param dos destination stream to receive the serialized representation; the caller owns and
   *     closes the stream.
   * @throws IOException if an I/O error occurs while writing the data to {@code dos}.
   * @throws MetadataUnresolvedException if unresolved child metadata prevents serialization;
   *     callers should resolve dependent entries first.
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

  /**
   * Indicates whether this document type carries a flag section in its serialized form.
   *
   * @return {@code true} for document types that include the flags section; {@code false}
   *     otherwise.
   */
  public boolean haveFlags() {
    return ((documentType == DocumentType.SIMPLE_REDIRECT)
        || (documentType == DocumentType.MULTI_LEVEL_METADATA)
        || (documentType == DocumentType.ARCHIVE_MANIFEST)
        || (documentType == DocumentType.ARCHIVE_INTERNAL_REDIRECT)
        || (documentType == DocumentType.ARCHIVE_METADATA_REDIRECT)
        || (documentType == DocumentType.SYMBOLIC_SHORTLINK));
  }

  /**
   * Returns the splitfile algorithm associated with this metadata.
   *
   * @return the {@link SplitfileAlgorithm} value; may be {@code null} when not a splitfile.
   */
  public SplitfileAlgorithm getSplitfileType() {
    return splitfileAlgorithm;
  }

  /**
   * Returns the data CHK keys for the splitfile when present.
   *
   * @return array of {@link ClientCHK} for data blocks, or {@code null} if keys are absent.
   */
  @SuppressWarnings("unused")
  public ClientCHK[] getSplitfileDataKeys() {
    return splitfileDataKeys;
  }

  /**
   * Returns the parity/check CHK keys for the splitfile when present.
   *
   * @return array of {@link ClientCHK} for check blocks, or {@code null} if keys are absent.
   */
  @SuppressWarnings("unused")
  public ClientCHK[] getSplitfileCheckKeys() {
    return splitfileCheckKeys;
  }

  /**
   * Indicates whether a compression codec is configured for this document.
   *
   * @return {@code true} when a codec is present; {@code false} otherwise.
   */
  public boolean isCompressed() {
    return compressionCodec != null;
  }

  /**
   * Returns the compression codec for this document when applicable.
   *
   * @return the codec identifier or {@code null} when no compression applies.
   */
  public COMPRESSOR_TYPE getCompressionCodec() {
    return compressionCodec;
  }

  /**
   * Returns the logical data length for this document in bytes.
   *
   * @return the data length; non‑negative.
   */
  public long dataLength() {
    return dataLength;
  }

  /**
   * Returns the raw splitfile parameters blob as stored in metadata.
   *
   * @return byte array for splitfile params, or {@code null} when not a splitfile.
   */
  public byte[] splitfileParams() {
    return splitfileParams;
  }

  /**
   * Returns the uncompressed data length for compressed content; equals data length otherwise.
   *
   * @return uncompressed length in bytes; non‑negative.
   */
  public long uncompressedDataLength() {
    return this.decompressedLength;
  }

  /**
   * Returns the resolved URI for this metadata when available.
   *
   * @return the {@link FreenetURI} that this metadata was resolved/inserted at, or {@code null}.
   */
  @SuppressWarnings("unused")
  public FreenetURI getResolvedURI() {
    return resolvedURI;
  }

  /**
   * Sets the resolved URI for this metadata (primarily used during insert flows).
   *
   * @param uri URI to associate with this metadata; may be {@code null} to clear.
   */
  public void resolve(FreenetURI uri) {
    this.resolvedURI = uri;
  }

  /**
   * Sets the resolved name (e.g., {@code .metadata-N}) for this metadata.
   *
   * @param name resolved name string to record; may be {@code null} to clear.
   */
  public void resolve(String name) {
    this.resolvedName = name;
  }

  /**
   * Serializes this metadata into a newly allocated random‑access bucket provided by the factory.
   *
   * @param bf factory used to allocate the destination bucket; must not be {@code null}.
   * @return a read‑only bucket containing the serialized metadata bytes.
   * @throws MetadataUnresolvedException if unresolved child metadata prevents serialization.
   * @throws IOException if an I/O error occurs while writing to the allocated bucket.
   */
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

  /**
   * Indicates whether either the resolved URI or resolved name has been set.
   *
   * @return {@code true} when a resolved identifier is present; {@code false} otherwise.
   */
  public boolean isResolved() {
    return (resolvedURI != null) || (resolvedName != null);
  }

  /** Switches this document to an archive manifest, clearing incompatible client metadata. */
  public void setArchiveManifest() {
    archiveType = ARCHIVE_TYPE.getArchiveType(clientMetadata.getMIMEType());
    clientMetadata.clear();
    documentType = DocumentType.ARCHIVE_MANIFEST;
  }

  /**
   * Returns the MIME type from client metadata if available.
   *
   * @return MIME type string or {@code null} when not set.
   */
  public String getMIMEType() {
    if (clientMetadata == null) return null;
    return clientMetadata.getMIMEType();
  }

  /**
   * Clears in‑memory splitfile key arrays and segment structures to reduce memory usage after they
   * are no longer needed.
   */
  @SuppressWarnings("unused")
  public void clearSplitfileKeys() {
    splitfileDataKeys = null;
    splitfileCheckKeys = null;
    segments = null;
  }

  /**
   * Returns the number of entries in the manifest map.
   *
   * @return total entries, including the default document when present.
   */
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
     * Add an item to the manifest.
     *
     * @param name the entry name to add; must be unique within the manifest and not {@code null}.
     * @param item the {@link Metadata} value for the entry; must not be {@code null}.
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

  /**
   * Produces a human‑readable dump of this metadata for diagnostics and testing.
   *
   * @return a multi‑line string with key fields and layout information.
   */
  public String dump() {
    StringBuilder sb = new StringBuilder();
    dump(0, sb);
    return sb.toString();
  }

  /**
   * Appends a human‑readable dump of this metadata to the supplied buffer.
   *
   * @param indent number of spaces to prefix each line with; must be non‑negative.
   * @param sb destination buffer to receive the dump text; must not be {@code null}.
   */
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
   *
   * @param o object expected to be a map representation of a directory; may be any {@link Map}
   *     implementation; keys must be strings.
   * @return a mutable {@code Map<String,Object>} view; either the original map (when already a
   *     {@link java.util.HashMap}) or a defensive copy; never {@code null}.
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

  /**
   * Returns the parsed metadata format version (0 or 1).
   *
   * @return the version number parsed from the serialized form.
   */
  public short getParsedVersion() {
    return parsedVersion;
  }

  /**
   * Indicates whether top‑level size/blocks information is present.
   *
   * @return {@code true} when any top‑level field is non‑zero; {@code false} otherwise.
   */
  public boolean hasTopData() {
    return topSize != 0 || topCompressedSize != 0 || topBlocksRequired != 0 || topBlocksTotal != 0;
  }

  /**
   * Returns the set of hashes for the final/original data, or {@code null} when absent.
   *
   * @return array of {@link HashResult} values, or {@code null}.
   */
  public HashResult[] getHashes() {
    return hashes;
  }

  /**
   * Returns the custom splitfile key when explicitly specified (not derived from hashes).
   *
   * @return the key bytes when {@code specifySplitfileKey} is {@code true}; otherwise an empty
   *     array.
   */
  public byte[] getCustomSplitfileKey() {
    if (specifySplitfileKey) return splitfileSingleCryptoKey;
    return new byte[0];
  }

  /**
   * Returns the splitfile crypto key used for all blocks when {@code parsedVersion >= 1}.
   *
   * @return the key bytes; may be {@code null} for older versions without a common key.
   */
  public byte[] getSplitfileCryptoKey() {
    return splitfileSingleCryptoKey;
  }

  /**
   * Returns the optional hash of this layer only (not the final data), or {@code null}.
   *
   * @return 32‑byte hash for this layer, or {@code null} when unavailable.
   */
  public byte[] getHashThisLayerOnly() {
    return hashThisLayerOnly;
  }

  /**
   * Returns the splitfile crypto algorithm identifier byte.
   *
   * @return the algorithm code.
   */
  public byte getSplitfileCryptoAlgorithm() {
    return splitfileSingleCryptoAlgorithm;
  }

  /**
   * Returns the declared top‑layer compatibility mode.
   *
   * @return top‑layer compatibility value.
   */
  public CompatibilityMode getTopCompatibilityMode() {
    return topCompatibilityMode;
  }

  /**
   * Returns whether top‑layer compression is disabled.
   *
   * @return {@code true} if compression is disabled; {@code false} otherwise.
   */
  public boolean getTopDontCompress() {
    return topDontCompress;
  }

  /**
   * Returns the numeric code for the top‑layer compatibility mode.
   *
   * @return short code corresponding to {@link #getTopCompatibilityMode()}.
   */
  public short getTopCompatibilityCode() {
    return topCompatibilityMode.code;
  }

  /**
   * Returns the minimum compatibility mode inferred for this metadata.
   *
   * @return lower bound for compatibility mode.
   */
  public CompatibilityMode getMinCompatMode() {
    return minCompatMode;
  }

  /**
   * Returns the maximum compatibility mode inferred for this metadata.
   *
   * @return upper bound for compatibility mode.
   */
  public CompatibilityMode getMaxCompatMode() {
    return maxCompatMode;
  }

  /**
   * Returns number of cross‑segment parity blocks per segment (0 when not used).
   *
   * @return count of cross‑segment parity blocks.
   */
  public int getCrossCheckBlocks() {
    return crossCheckBlocks;
  }

  /**
   * Returns number of check/parity blocks per segment.
   *
   * @return parity/check blocks per segment.
   */
  public int getCheckBlocksPerSegment() {
    return checkBlocksPerSegment;
  }

  /**
   * Returns number of data blocks per segment (not including cross‑segment blocks).
   *
   * @return data blocks per segment.
   */
  public int getDataBlocksPerSegment() {
    return blocksPerSegment;
  }

  /**
   * Returns the number of segments implied by the splitfile layout.
   *
   * @return segment count; non‑negative.
   */
  public int getSegmentCount() {
    return segmentCount;
  }

  // Note: legacy behavior retained for compatibility; segments are cleared after being grabbed to
  // reduce memory usage.
  /**
   * Returns and clears the current segment key list array to reduce memory usage.
   *
   * @return previously stored {@link SplitFileSegmentKeys} array, or {@code null} when none
   *     present.
   * @throws FetchException if raw key arrays exist but segment structures are missing; re‑parse
   *     metadata in that case.
   */
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

  /**
   * Returns the immutable segment key lists for this splitfile, or {@code null} if not built.
   *
   * @return an array of {@link SplitFileSegmentKeys}, or {@code null} when keys were not populated.
   * @throws FetchException if the keys were cleared while the metadata still holds raw key arrays;
   *     callers should re‑parse the metadata in that case.
   */
  public SplitFileSegmentKeys[] getSegmentKeys() throws FetchException {
    synchronized (this) {
      if (segments == null && splitfileDataKeys != null && splitfileCheckKeys != null)
        throw new FetchException(
            FetchExceptionMode.INTERNAL_ERROR,
            "Please restart the download, need to re-parse metadata due to internal changes");
      return segments;
    }
  }

  /**
   * Returns the number of trailing segments that lose one data block for balancing.
   *
   * @return number of trailing segments with one less data block.
   */
  public int getDeductBlocksFromSegments() {
    return deductBlocksFromSegments;
  }

  /**
   * Return a best‑guess compatibility mode, guaranteed not to be {@code COMPAT_UNKNOWN} or {@code
   * COMPAT_CURRENT}.
   *
   * @return the most appropriate {@link CompatibilityMode} for this metadata when an exact top mode
   *     is not available.
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

  /**
   * Returns whether the provided byte is a recognized splitfile crypto algorithm code.
   *
   * @param cryptoAlgorithm algorithm identifier byte to test.
   * @return {@code true} for valid codes, {@code false} otherwise.
   */
  public static boolean isValidSplitfileCryptoAlgorithm(byte cryptoAlgorithm) {
    return cryptoAlgorithm == 0 || Key.isValidCryptoAlgorithm(cryptoAlgorithm);
  }
}

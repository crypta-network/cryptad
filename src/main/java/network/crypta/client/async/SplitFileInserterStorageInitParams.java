package network.crypta.client.async;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Holds the inputs required to initialize a splitfile insert storage session.
 *
 * <p>This parameter holder is populated when a new splitfile insert is started. It captures the
 * original data buffer, encoding configuration, metadata, and runtime helpers needed to construct
 * {@link SplitFileInserterStorage}. Values are stored as provided with no validation or defensive
 * copying.
 *
 * @see SplitFileInserterStorage
 * @see SplitFileInserterStorageRuntimeParams
 */
public final class SplitFileInserterStorageInitParams {
  LockableRandomAccessBuffer originalData;
  long decompressedLength;
  SplitFileInserterStorageRuntimeParams runtime;
  COMPRESSOR_TYPE compressionCodec;
  ClientMetadata meta;
  boolean isMetadata;
  ARCHIVE_TYPE archiveType;
  LockableRandomAccessBufferFactory rafFactory;
  boolean persistent;
  InsertContext ctx;
  byte splitfileCryptoAlgorithm;
  byte[] splitfileCryptoKey;
  byte[] hashThisLayerOnly;
  HashResult[] hashes;
  BucketFactory tempBucketFactory;
  ChecksumChecker checker;
  boolean topDontCompress;
  int topRequiredBlocks;
  int topTotalBlocks;
  long origDataSize;
  long origCompressedDataSize;

  private SplitFileInserterStorageInitParams() {}

  /**
   * Fluent builder for {@link SplitFileInserterStorageInitParams}.
   *
   * <p>The builder stores references as-is and performs no validation.
   */
  public static final class Builder {
    private LockableRandomAccessBuffer originalData;
    private long decompressedLength;
    private SplitFileInserterStorageRuntimeParams runtime;
    private COMPRESSOR_TYPE compressionCodec;
    private ClientMetadata meta;
    private boolean isMetadata;
    private ARCHIVE_TYPE archiveType;
    private LockableRandomAccessBufferFactory rafFactory;
    private boolean persistent;
    private InsertContext ctx;
    private byte splitfileCryptoAlgorithm;
    private byte[] splitfileCryptoKey;
    private byte[] hashThisLayerOnly;
    private HashResult[] hashes;
    private BucketFactory tempBucketFactory;
    private ChecksumChecker checker;
    private boolean topDontCompress;
    private int topRequiredBlocks;
    private int topTotalBlocks;
    private long origDataSize;
    private long origCompressedDataSize;

    /**
     * Sets the original data buffer to insert.
     *
     * @param v original data buffer
     * @return this builder for chaining
     */
    public Builder originalData(LockableRandomAccessBuffer v) {
      this.originalData = v;
      return this;
    }

    /**
     * Sets the decompressed length of the input.
     *
     * @param v decompressed length in bytes
     * @return this builder for chaining
     */
    public Builder decompressedLength(long v) {
      this.decompressedLength = v;
      return this;
    }

    /**
     * Sets runtime collaborators for storage construction.
     *
     * @param v runtime parameter group
     * @return this builder for chaining
     */
    public Builder runtime(SplitFileInserterStorageRuntimeParams v) {
      this.runtime = v;
      return this;
    }

    /**
     * Sets the compression codec to use at the top level.
     *
     * @param v compression codec or {@code null} for none
     * @return this builder for chaining
     */
    public Builder compressionCodec(COMPRESSOR_TYPE v) {
      this.compressionCodec = v;
      return this;
    }

    /**
     * Sets the optional client metadata.
     *
     * @param v client metadata
     * @return this builder for chaining
     */
    public Builder meta(ClientMetadata v) {
      this.meta = v;
      return this;
    }

    /**
     * Sets whether the payload is metadata.
     *
     * @param v {@code true} if the payload is metadata
     * @return this builder for chaining
     */
    public Builder isMetadata(boolean v) {
      this.isMetadata = v;
      return this;
    }

    /**
     * Sets the archive type for the insert.
     *
     * @param v archive type or {@code null} if none
     * @return this builder for chaining
     */
    public Builder archiveType(ARCHIVE_TYPE v) {
      this.archiveType = v;
      return this;
    }

    /**
     * Sets the RAF factory used for persistent storage.
     *
     * @param v RAF factory
     * @return this builder for chaining
     */
    public Builder rafFactory(LockableRandomAccessBufferFactory v) {
      this.rafFactory = v;
      return this;
    }

    /**
     * Sets whether the storage is persistent.
     *
     * @param v persistence flag
     * @return this builder for chaining
     */
    public Builder persistent(boolean v) {
      this.persistent = v;
      return this;
    }

    /**
     * Sets the insert context.
     *
     * @param v insert context
     * @return this builder for chaining
     */
    public Builder ctx(InsertContext v) {
      this.ctx = v;
      return this;
    }

    /**
     * Sets the splitfile crypto algorithm identifier.
     *
     * @param v crypto algorithm identifier
     * @return this builder for chaining
     */
    public Builder splitfileCryptoAlgorithm(byte v) {
      this.splitfileCryptoAlgorithm = v;
      return this;
    }

    /**
     * Sets the splitfile crypto key.
     *
     * @param v raw splitfile crypto key
     * @return this builder for chaining
     */
    public Builder splitfileCryptoKey(byte[] v) {
      this.splitfileCryptoKey = v;
      return this;
    }

    /**
     * Sets the layer-only hash value.
     *
     * @param v layer-only hash bytes
     * @return this builder for chaining
     */
    public Builder hashThisLayerOnly(byte[] v) {
      this.hashThisLayerOnly = v;
      return this;
    }

    /**
     * Sets the precomputed hash results.
     *
     * @param v hash results array
     * @return this builder for chaining
     */
    public Builder hashes(HashResult[] v) {
      this.hashes = v;
      return this;
    }

    /**
     * Sets the temporary bucket factory used during encoding.
     *
     * @param v bucket factory
     * @return this builder for chaining
     */
    public Builder tempBucketFactory(BucketFactory v) {
      this.tempBucketFactory = v;
      return this;
    }

    /**
     * Sets the checksum checker used to wrap sections.
     *
     * @param v checksum checker
     * @return this builder for chaining
     */
    public Builder checker(ChecksumChecker v) {
      this.checker = v;
      return this;
    }

    /**
     * Sets whether to skip top-level compression in metadata.
     *
     * @param v {@code true} to skip top-level compression
     * @return this builder for chaining
     */
    public Builder topDontCompress(boolean v) {
      this.topDontCompress = v;
      return this;
    }

    /**
     * Sets the number of required blocks at the top level.
     *
     * @param v required block count
     * @return this builder for chaining
     */
    public Builder topRequiredBlocks(int v) {
      this.topRequiredBlocks = v;
      return this;
    }

    /**
     * Sets the total number of blocks at the top level.
     *
     * @param v total block count
     * @return this builder for chaining
     */
    public Builder topTotalBlocks(int v) {
      this.topTotalBlocks = v;
      return this;
    }

    /**
     * Sets the original data size in bytes.
     *
     * @param v original data size
     * @return this builder for chaining
     */
    public Builder origDataSize(long v) {
      this.origDataSize = v;
      return this;
    }

    /**
     * Sets the original compressed data size in bytes.
     *
     * @param v original compressed data size
     * @return this builder for chaining
     */
    public Builder origCompressedDataSize(long v) {
      this.origCompressedDataSize = v;
      return this;
    }

    /**
     * Builds a {@link SplitFileInserterStorageInitParams} snapshot.
     *
     * @return new parameter snapshot
     */
    public SplitFileInserterStorageInitParams build() {
      SplitFileInserterStorageInitParams p = new SplitFileInserterStorageInitParams();
      p.originalData = originalData;
      p.decompressedLength = decompressedLength;
      p.runtime = runtime;
      p.compressionCodec = compressionCodec;
      p.meta = meta;
      p.isMetadata = isMetadata;
      p.archiveType = archiveType;
      p.rafFactory = rafFactory;
      p.persistent = persistent;
      p.ctx = ctx;
      p.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
      p.splitfileCryptoKey = splitfileCryptoKey;
      p.hashThisLayerOnly = hashThisLayerOnly;
      p.hashes = hashes;
      p.tempBucketFactory = tempBucketFactory;
      p.checker = checker;
      p.topDontCompress = topDontCompress;
      p.topRequiredBlocks = topRequiredBlocks;
      p.topTotalBlocks = topTotalBlocks;
      p.origDataSize = origDataSize;
      p.origCompressedDataSize = origCompressedDataSize;
      return p;
    }
  }
}

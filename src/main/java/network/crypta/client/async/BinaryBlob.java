package network.crypta.client.async;

import com.onionnetworks.util.FileUtil;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyVerifyException;

/**
 * Utility for reading and writing the on‑disk Binary Blob format used to bundle key blocks.
 *
 * <p>This class provides a small, self‑contained framing format: a file starts with a magic value
 * and an overall format version, followed by a sequence of typed blobs. Each blob begins with a
 * fixed header containing a length (in bytes), a type identifier, and a per‑type version. Two blob
 * types are currently used: a block record that carries a single key block and an explicit end
 * marker. Callers typically write a header once, stream one or more blocks, then terminate with the
 * end marker. The corresponding reader validates structure and yields blocks to the provided
 * collector.
 *
 * <p>The format is designed for simple concatenation and streaming I/O. It does not compress or
 * encrypt the payload; higher layers are responsible for confidentiality and integrity. Numeric
 * fields are big‑endian and lengths include only the payload that follows the blob header. The
 * implementation performs minimal validation to preserve streaming characteristics while still
 * catching obvious corruption.
 *
 * <ul>
 *   <li>Responsibilities: emit and parse Binary Blob headers and records.
 *   <li>Mutability: stateless utility; all methods are static and thread‑safe.
 *   <li>Failure modes: short reads, unsupported versions, and malformed payload sizes.
 * </ul>
 *
 * <p>All members are static; instantiation is not allowed.
 */
public final class BinaryBlob {
  private BinaryBlob() {
    // Prevent instantiation of utility class
  }

  /**
   * File signature written at the beginning of every Binary Blob stream.
   *
   * <p>The value is a fixed 64‑bit big‑endian constant chosen to minimize collision with common
   * file types. Readers must compare the first eight bytes of an input stream with this value to
   * recognize the format and reject unrelated data. The constant is stable across versions and does
   * not imply compatibility of subsequent records.
   */
  public static final long BINARY_BLOB_MAGIC = 0x6d58249f72d67ed9L;

  /**
   * Overall file format version following {@link #BINARY_BLOB_MAGIC} in the header.
   *
   * <p>This is a 16‑bit unsigned value stored as a Java {@code short}. A reader must verify the
   * value and fail when it does not match the supported version. The current version is {@code 0},
   * which indicates the record shapes emitted by this implementation.
   */
  public static final short BINARY_BLOB_OVERALL_VERSION = 0;

  /**
   * Writes the Binary Blob file header to the provided stream.
   *
   * <p>The header consists of {@link #BINARY_BLOB_MAGIC} followed by {@link
   * #BINARY_BLOB_OVERALL_VERSION}. After this call returns, callers may write one or more blob
   * records using {@link #writeKey(DataOutputStream, KeyBlock, Key)} and finish with {@link
   * #writeEndBlob(DataOutputStream)}.
   *
   * @param binaryBlobStream destination stream; not closed by this method. The stream must be open
   *     and writable; buffering is the caller's responsibility.
   * @throws IOException if writing to the underlying stream fails, for example due to a closed
   *     channel or filesystem error.
   */
  public static void writeBinaryBlobHeader(DataOutputStream binaryBlobStream) throws IOException {
    binaryBlobStream.writeLong(BinaryBlob.BINARY_BLOB_MAGIC);
    binaryBlobStream.writeShort(BinaryBlob.BINARY_BLOB_OVERALL_VERSION);
  }

  /**
   * Writes a single key block record to the stream.
   *
   * <p>The method serializes the supplied {@code block} in the Binary Blob record format. The
   * record length is computed from the constituent arrays and written as part of the blob header.
   * The method does not flush or close the stream. Callers typically write multiple records in
   * sequence and terminate the stream with {@link #writeEndBlob(DataOutputStream)}.
   *
   * @param binaryBlobStream destination stream; remains open. Must support writing the full record
   *     without blocking indefinitely; callers should provide adequate buffering.
   * @param block fully formed key block supplying headers, data, and optional public key bytes; its
   *     getters must return arrays sized consistently with the format fields.
   * @param key key whose encoded bytes are written alongside the block; the key type identifier is
   *     derived from the block itself.
   * @throws IOException if writing to the underlying stream fails at any point during
   *     serialization.
   */
  public static void writeKey(DataOutputStream binaryBlobStream, KeyBlock block, Key key)
      throws IOException {
    byte[] keyData = key.getKeyBytes();
    byte[] headers = block.getRawHeaders();
    byte[] data = block.getRawData();
    byte[] pubkey = block.getPubkeyBytes();
    writeBlobHeader(
        binaryBlobStream,
        BLOB_BLOCK,
        BLOB_BLOCK_VERSION,
        9 + keyData.length + headers.length + data.length + (pubkey == null ? 0 : pubkey.length));
    binaryBlobStream.writeShort(block.getKey().getType());
    binaryBlobStream.writeByte(keyData.length);
    binaryBlobStream.writeShort(headers.length);
    binaryBlobStream.writeShort(data.length);
    binaryBlobStream.writeShort(pubkey == null ? 0 : pubkey.length);
    binaryBlobStream.write(keyData);
    binaryBlobStream.write(headers);
    binaryBlobStream.write(data);
    if (pubkey != null) binaryBlobStream.write(pubkey);
  }

  static final short BLOB_BLOCK = 1;
  static final short BLOB_BLOCK_VERSION = 0;
  static final short BLOB_END = 2;
  static final short BLOB_END_VERSION = 0;

  /**
   * Media type string identifying Binary Blob content for transfer or storage metadata.
   *
   * <p>The value is stable and can be used in HTTP {@code Content-Type} headers and similar
   * metadata carriers. It does not convey version information; consumers must inspect the stream
   * header to determine compatibility.
   */
  public static final String MIME_TYPE = "application/x-freenet-binary-blob";

  static void writeBlobHeader(
      DataOutputStream binaryBlobStream, short type, short version, int length) throws IOException {
    binaryBlobStream.writeInt(length);
    binaryBlobStream.writeShort(type);
    binaryBlobStream.writeShort(version);
  }

  /**
   * Writes an explicit end marker blob to the stream.
   *
   * <p>The marker carries no payload and allows readers to terminate cleanly without relying on end
   * of file. After calling this method, callers may continue to use the stream for other unrelated
   * data if desired; the Binary Blob reader stops at the marker.
   *
   * @param binaryBlobStream destination stream to receive the zero‑length end record; not closed by
   *     this method.
   * @throws IOException if the marker header cannot be written due to an I/O failure.
   */
  public static void writeEndBlob(DataOutputStream binaryBlobStream) throws IOException {
    writeBlobHeader(binaryBlobStream, BinaryBlob.BLOB_END, BinaryBlob.BLOB_END_VERSION, 0);
  }

  /**
   * Reads a Binary Blob stream from the given input and delivers parsed blocks to a collector.
   *
   * <p>The method validates the magic and overall version, then iterates over blob records until an
   * end marker is encountered or the stream ends. When {@code tolerant} is {@code true}, unknown
   * blob types are skipped using the advertised length; otherwise such records cause a format
   * exception. The input is closed when parsing finishes, either on end marker or natural EOF.
   *
   * @param dis input stream positioned at the beginning of a Binary Blob; the method consumes the
   *     entire blob and closes the stream on completion or on end marker.
   * @param blocks collector that receives each successfully decoded key block in encounter order;
   *     implementations may persist, buffer, or process blocks as they arrive.
   * @param tolerant whether to ignore unknown blob types by skipping their payload or to fail fast
   *     with a format error for strict validation.
   * @throws IOException if the underlying input fails to provide the required number of bytes or a
   *     read operation fails due to I/O errors.
   * @throws BinaryBlobFormatException if the magic, version, sizes, or record types are invalid, or
   *     when a block record cannot be decoded into a valid key.
   */
  public static void readBinaryBlob(DataInputStream dis, BlockSet blocks, boolean tolerant)
      throws IOException, BinaryBlobFormatException {
    long magic = dis.readLong();
    if (magic != BinaryBlob.BINARY_BLOB_MAGIC) throw new BinaryBlobFormatException("Bad magic");
    short version = dis.readShort();
    if (version != BinaryBlob.BINARY_BLOB_OVERALL_VERSION)
      throw new BinaryBlobFormatException("Unknown overall version");

    while (true) {
      long blobLength;
      try {
        blobLength = dis.readInt() & 0xFFFFFFFFL;
      } catch (EOFException _) {
        // End of file
        dis.close();
        return;
      }
      short blobType = dis.readShort();
      short blobVer = dis.readShort();

      switch (blobType) {
        case BLOB_END -> {
          dis.close();
          return;
        }
        case BLOB_BLOCK -> {
          KeyBlock block = readBlock(dis, blobLength, blobVer);
          blocks.add(block);
        }
        default -> {
          if (tolerant) {
            FileUtil.skipFully(dis, blobLength);
          } else {
            throw new BinaryBlobFormatException("Unknown blob type: " + blobType);
          }
        }
      }
    }
  }

  private static KeyBlock readBlock(DataInputStream dis, long blobLength, short blobVer)
      throws IOException, BinaryBlobFormatException {
    if (blobVer != BinaryBlob.BLOB_BLOCK_VERSION)
      // Even if tolerant, if we can't read a blob there probably isn't much we can do.
      throw new BinaryBlobFormatException("Unknown block blob version");
    if (blobLength < 9) throw new BinaryBlobFormatException("Block blob too short");
    short keyType = dis.readShort();
    int keyLen = dis.readUnsignedByte();
    int headersLen = dis.readUnsignedShort();
    int dataLen = dis.readUnsignedShort();
    int pubkeyLen = dis.readUnsignedShort();
    int total = 9 + keyLen + headersLen + dataLen + pubkeyLen;
    if (blobLength != total) {
      throw new BinaryBlobFormatException(
          "Binary blob not same length as data: blobLength=" + blobLength + " total=" + total);
    }
    byte[] keyBytes = new byte[keyLen];
    byte[] headersBytes = new byte[headersLen];
    byte[] dataBytes = new byte[dataLen];
    byte[] pubkeyBytes = new byte[pubkeyLen];
    dis.readFully(keyBytes);
    dis.readFully(headersBytes);
    dis.readFully(dataBytes);
    dis.readFully(pubkeyBytes);
    try {
      return Key.createBlock(keyType, keyBytes, headersBytes, dataBytes, pubkeyBytes);
    } catch (KeyVerifyException e) {
      throw new BinaryBlobFormatException("Invalid key: " + e.getMessage(), e);
    }
  }
}

package network.crypta.keys;

import java.io.IOException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;

/**
 * Represents a decodable key block that is associated with a {@link ClientKey}.
 *
 * <p>This interface exposes methods to decode the block either into a {@link Bucket} using a
 * provided {@link BucketFactory} or directly into memory. Implementations also expose whether the
 * block carries metadata rather than payload data.
 *
 * <p>It is intentionally not a subtype of {@link KeyBlock}. Equality for client key blocks must
 * take the associated {@link ClientKey} into account; two blocks with identical underlying content
 * but different client keys are not equal. Treating it as a different type avoids violating {@link
 * Object#equals(Object)} symmetry with {@link KeyBlock}.
 */
public interface ClientKeyBlock {

  /**
   * Decodes the block using the associated {@link ClientKey}.
   *
   * <p>The decoded content is written to a {@link Bucket} allocated by the supplied {@link
   * BucketFactory}.
   *
   * @param factory the factory used to create the destination {@link Bucket}; must not be null
   * @param maxLength the maximum allowed size of the decoded data, in bytes
   * @param dontDecompress when {@code true}, returns raw decoded bytes without decompression if the
   *     format supports compression
   * @return a {@link Bucket} containing the decoded content
   * @throws KeyDecodeException if the block cannot be decoded (for example, invalid key or corrupt
   *     data)
   * @throws IOException on I/O errors during decoding
   */
  Bucket decode(BucketFactory factory, int maxLength, boolean dontDecompress)
      throws KeyDecodeException, IOException;

  /**
   * Indicates whether the block contains metadata rather than payload data.
   *
   * @return {@code true} if the block contains metadata; {@code false} if it contains payload data
   */
  boolean isMetadata();

  /**
   * Returns the client-level key associated with this block.
   *
   * @return the {@link ClientKey} used to decode the block
   */
  ClientKey getClientKey();

  /**
   * Decodes the block entirely into memory and returns the resulting bytes.
   *
   * <p>This is a convenience counterpart to {@link #decode(BucketFactory, int, boolean)} that does
   * not require a {@link BucketFactory}.
   *
   * @return a new byte array containing the decoded content
   * @throws KeyDecodeException if the block cannot be decoded
   */
  byte[] memoryDecode() throws KeyDecodeException;

  /**
   * Returns the underlying low-level {@link KeyBlock} representation.
   *
   * @return the underlying key block
   */
  KeyBlock getBlock();

  /**
   * Returns the low-level {@link Key} that identifies the block at the storage layer.
   *
   * @return the low-level key
   */
  Key getKey();

  /**
   * Compares this object to another for equality.
   *
   * <p>Implementations consider both the content and the associated {@link ClientKey}. Two client
   * key blocks with identical content but different client keys are not equal. Consequently, a
   * {@code ClientKeyBlock} is not equal to its raw {@link KeyBlock} representation.
   *
   * @param o the object to compare with
   * @return {@code true} if the objects are equal; otherwise {@code false}
   */
  @Override
  boolean equals(Object o);

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * @return a hash code value for this object
   */
  @Override
  int hashCode();
}

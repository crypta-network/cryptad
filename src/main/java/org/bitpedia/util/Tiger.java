package org.bitpedia.util;

import java.security.DigestException;
import java.security.MessageDigest;
import org.bouncycastle.crypto.digests.TigerDigest;

/**
 * JCA {@link MessageDigest} implementation for the 192-bit Tiger hash.
 *
 * <p>This implementation delegates all hashing operations to BouncyCastle's {@link TigerDigest}
 * while exposing the standard {@link MessageDigest} SPI used by the rest of the codebase.
 */
public final class Tiger extends MessageDigest implements Cloneable {

  /** Fixed-size Tiger digest length in bytes (192 bits). */
  private static final int HASH_LENGTH = 24;

  private final TigerDigest digest;

  /** Creates a Tiger digest with a fresh internal {@link TigerDigest} instance. */
  public Tiger() {
    super("Tiger");
    this.digest = new TigerDigest();
  }

  private Tiger(TigerDigest digest) {
    super("Tiger");
    this.digest = digest;
  }

  @Override
  public int engineGetDigestLength() {
    return HASH_LENGTH;
  }

  @Override
  public void engineReset() {
    digest.reset();
  }

  @Override
  public void engineUpdate(byte input) {
    digest.update(input);
  }

  @Override
  public void engineUpdate(byte[] input, int offset, int len) {
    if (input == null) {
      throw new NullPointerException("input");
    }
    if (offset < 0 || len < 0 || offset + len > input.length) {
      // Match historical behaviour of the previous implementation.
      throw new ArrayIndexOutOfBoundsException(offset);
    }
    digest.update(input, offset, len);
  }

  @Override
  public byte[] engineDigest() {
    byte[] out = new byte[HASH_LENGTH];
    try {
      engineDigest(out, 0, HASH_LENGTH);
      return out;
    } catch (DigestException e) {
      return null;
    }
  }

  @Override
  public int engineDigest(byte[] buf, int offset, int len) throws DigestException {
    if (len < HASH_LENGTH) {
      throw new DigestException("partial digests not returned");
    }
    if (buf.length - offset < HASH_LENGTH) {
      throw new DigestException("insufficient space in output buffer to store the digest");
    }
    return digest.doFinal(buf, offset);
  }

  /**
   * Creates a copy of this {@link Tiger} instance with an independent internal {@link TigerDigest}
   * state.
   */
  @Override
  public Object clone() throws CloneNotSupportedException {
    try {
      return new Tiger(new TigerDigest(digest));
    } catch (Exception e) {
      throw new CloneNotSupportedException(e.toString());
    }
  }
}

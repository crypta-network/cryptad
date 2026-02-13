package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.math.BigInteger;
import java.util.Random;
import network.crypta.support.Base64;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;

public final class DSAPrivateKey extends CryptoKey {
  @Serial private static final long serialVersionUID = -1;

  private final BigInteger x;

  public DSAPrivateKey(BigInteger x, DSAGroup g) {
    this.x = x;
    if (x.signum() != 1 || x.compareTo(g.getQ()) >= 0 || x.compareTo(BigInteger.ZERO) <= 0)
      throw new IllegalArgumentException();
  }

  // Intentionally no byte[] constructor to avoid sign confusions with BigInteger.

  public DSAPrivateKey(DSAGroup g, Random r) {
    BigInteger tempX;
    do {
      tempX = new BigInteger(256, r);
    } while (tempX.compareTo(g.getQ()) >= 0 || tempX.compareTo(BigInteger.ZERO) <= 0);
    this.x = tempX;
  }

  @SuppressWarnings("unused")
  protected DSAPrivateKey() {
    // For serialization.
    x = null;
  }

  @Override
  public String keyType() {
    return "DSA.s";
  }

  public BigInteger getX() {
    return x;
  }

  public static CryptoKey read(InputStream i, DSAGroup g) throws IOException {
    return new DSAPrivateKey(Util.readMPI(i), g);
  }

  @Override
  public String toLongString() {
    return "x=" + HexUtil.biToHex(x);
  }

  // No readFromField() variant retained; callers should use read(InputStream, DSAGroup).

  @Override
  public byte[] asBytes() {
    return Util.mpiBytes(x);
  }

  @Override
  public byte[] fingerprint() {
    return fingerprint(new BigInteger[] {x});
  }

  public SimpleFieldSet asFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("x", Base64.encode(x.toByteArray()));
    return fs;
  }

  public static DSAPrivateKey create(SimpleFieldSet fs, DSAGroup group)
      throws IllegalBase64Exception {
    BigInteger xDecoded = new BigInteger(1, Base64.decode(fs.get("x")));
    if (xDecoded.bitLength() > 512) throw new IllegalBase64Exception("Probably a pubkey");
    return new DSAPrivateKey(xDecoded, group);
  }
}

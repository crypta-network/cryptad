package network.crypta.crypt;

import java.io.*;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import network.crypta.support.HexUtil;
import network.crypta.support.Logger;

public abstract class CryptoKey implements CryptoElement, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  CryptoKey() {}

  public static CryptoKey read(InputStream i) throws IOException, CryptFormatException {
    DataInputStream dis = new DataInputStream(i);
    String type = dis.readUTF();
    try {
      Class<?> keyClass = Class.forName(type);
      Method m = keyClass.getMethod("read", InputStream.class);
      return (CryptoKey) m.invoke(null, dis);
    } catch (Exception e) {
      e.printStackTrace();
      if (e instanceof CryptFormatException exception) throw exception;
      if (e instanceof IOException exception) throw exception;
      Logger.error(CryptoKey.class, "Unknown exception while reading CryptoKey", e);
      return null;
    }
  }

  //	public abstract void write(OutputStream o) throws IOException;

  public abstract String keyType();

  public abstract byte[] fingerprint();

  public abstract byte[] asBytes();

  protected byte[] fingerprint(BigInteger[] quantities) {
    MessageDigest shactx = HashType.SHA1.get();
    for (BigInteger quantity : quantities) {
      byte[] mpi = Util.MPIbytes(quantity);
      shactx.update(mpi, 0, mpi.length);
    }
    return shactx.digest();
  }

  public String verboseToString() {
    return String.valueOf(this) + '\t' + fingerprintToString();
  }

  @Override
  public String toString() {
    StringBuilder b = new StringBuilder(keyType().length() + 1 + 4);
    b.append(keyType()).append('/');
    HexUtil.bytesToHexAppend(fingerprint(), 16, 4, b);
    return b.toString();
  }

  //	protected void write(OutputStream o, String clazz) throws IOException {
  //		UTF8.writeWithLength(o, clazz);
  //	}
  //
  public String fingerprintToString() {
    String fphex = HexUtil.bytesToHex(fingerprint());
    String b =
        fphex.substring(0, 4)
            + ' '
            + fphex.substring(4, 8)
            + ' '
            + fphex.substring(8, 12)
            + ' '
            + fphex.substring(12, 16)
            + ' '
            + fphex.substring(16, 20)
            + "  "
            + fphex.substring(20, 24)
            + ' '
            + fphex.substring(24, 28)
            + ' '
            + fphex.substring(28, 32)
            + ' '
            + fphex.substring(32, 36)
            + ' '
            + fphex.substring(36, 40);
    return b;
  }
}

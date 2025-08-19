package network.crypta.keys;

import java.io.Serial;
import java.net.MalformedURLException;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.support.Logger;

/**
 * An insertable USK.
 *
 * <p>Changes from an ordinary USK: - It has a private key - getURI() doesn't include ,extra -
 * constructor from URI doesn't need or want ,extra - It has a getUSK() method which gets the public
 * USK
 */
public class InsertableUSK extends USK {

  @Serial private static final long serialVersionUID = 1L;
  public final DSAPrivateKey privKey;

  public static InsertableUSK createInsertable(FreenetURI uri, boolean persistent)
      throws MalformedURLException {
    if (!uri.getKeyType().equalsIgnoreCase("USK")) throw new MalformedURLException();
    InsertableClientSSK ssk = InsertableClientSSK.create(uri.setKeyType("SSK"));
    return new InsertableUSK(
        ssk.docName,
        ssk.pubKeyHash,
        ssk.cryptoKey,
        ssk.privKey,
        uri.getSuggestedEdition(),
        ssk.cryptoAlgorithm);
  }

  InsertableUSK(
      String docName,
      byte[] pubKeyHash,
      byte[] cryptoKey,
      DSAPrivateKey key,
      long suggestedEdition,
      byte cryptoAlgorithm)
      throws MalformedURLException {
    super(pubKeyHash, cryptoKey, docName, suggestedEdition, cryptoAlgorithm);
    if (cryptoKey.length != ClientSSK.CRYPTO_KEY_LENGTH)
      throw new MalformedURLException(
          "Decryption key wrong length: "
              + cryptoKey.length
              + " should be "
              + ClientSSK.CRYPTO_KEY_LENGTH);
    this.privKey = key;
  }

  public USK getUSK() {
    return new USK(pubKeyHash, cryptoKey, siteName, suggestedEdition, cryptoAlgorithm);
  }

  public InsertableClientSSK getInsertableSSK(long ver) {
    return getInsertableSSK(siteName + SEPARATOR + ver);
  }

  public InsertableClientSSK getInsertableSSK(String string) {
    try {
      return new InsertableClientSSK(
          string,
          pubKeyHash,
          new DSAPublicKey(getCryptoGroup(), privKey),
          privKey,
          cryptoKey,
          cryptoAlgorithm);
    } catch (MalformedURLException e) {
      Logger.error(this, "Caught " + e + " should not be possible in USK.getSSK", e);
      throw new Error(e);
    }
  }

  public InsertableUSK privCopy(long edition) {
    if (edition == suggestedEdition) return this;
    try {
      return new InsertableUSK(siteName, pubKeyHash, cryptoKey, privKey, edition, cryptoAlgorithm);
    } catch (MalformedURLException e) {
      throw new Error(e);
    }
  }

  public final DSAGroup getCryptoGroup() {
    return Global.DSAgroupBigA;
  }
}

package network.crypta.keys;

import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.support.math.MersenneTwister;

public class ClientKSK extends InsertableClientSSK {

  @Serial private static final long serialVersionUID = 1L;
  final String keyword;

  private ClientKSK(
      String keyword,
      byte[] pubKeyHash,
      DSAPublicKey pubKey,
      DSAPrivateKey privKey,
      byte[] keywordHash)
      throws MalformedURLException {
    super(keyword, pubKeyHash, pubKey, privKey, keywordHash, Key.ALGO_AES_PCFB_256_SHA256);
    this.keyword = keyword;
  }

  protected ClientKSK() {
    // For serialization.
    keyword = null;
  }

  @Override
  public FreenetURI getURI() {
    return new FreenetURI("KSK", keyword);
  }

  public static InsertableClientSSK create(FreenetURI uri) {
    if (!uri.getKeyType().equals("KSK")) throw new IllegalArgumentException();
    return create(uri.getDocName());
  }

  public static ClientKSK create(String keyword) {
    MessageDigest md256 = SHA256.getMessageDigest();
    byte[] keywordHash = md256.digest(keyword.getBytes(StandardCharsets.UTF_8));
    MersenneTwister mt = MersenneTwister.createUnsynchronized(keywordHash);
    DSAPrivateKey privKey = new DSAPrivateKey(Global.DSAgroupBigA, mt);
    DSAPublicKey pubKey = new DSAPublicKey(Global.DSAgroupBigA, privKey);
    byte[] pubKeyHash = md256.digest(pubKey.asBytes());
    try {
      return new ClientKSK(keyword, pubKeyHash, pubKey, privKey, keywordHash);
    } catch (MalformedURLException e) {
      throw new Error(e);
    }
  }
}

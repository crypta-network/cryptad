package network.crypta.crypt;

import java.security.interfaces.ECPublicKey;
import network.crypta.support.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ECDHLightContext extends KeyAgreementSchemeContext {
  private static final Logger LOG = LoggerFactory.getLogger(ECDHLightContext.class);

  static {
  }

  public final ECDH ecdh;

  @Override
  public String toString() {
    return super.toString();
  }

  public ECDHLightContext(ECDH.Curves curve) {
    this.ecdh = new ECDH(curve);
    this.lastUsedTime = System.currentTimeMillis();
  }

  public ECPublicKey getPublicKey() {
    return ecdh.getPublicKey();
  }

  /*
   * Calling the following is costy; avoid
   */
  public byte[] getHMACKey(ECPublicKey peerExponential) {
    synchronized (this) {
      lastUsedTime = System.currentTimeMillis();
    }
    byte[] sharedKey = ecdh.getAgreedSecret(peerExponential);

    if (LOG.isDebugEnabled()) {
      LOG.debug("Curve in use: " + ecdh.curve.toString());
      if (LOG.isDebugEnabled()) {
        LOG.debug("My exponential: " + HexUtil.bytesToHex(ecdh.getPublicKey().getEncoded()));
        LOG.debug("Peer's exponential: " + HexUtil.bytesToHex(peerExponential.getEncoded()));
        LOG.debug("SharedSecret = " + HexUtil.bytesToHex(sharedKey));
      }
    }

    return sharedKey;
  }

  @Override
  public byte[] getPublicKeyNetworkFormat() {
    return ecdh.getPublicKeyNetworkFormat();
  }
}

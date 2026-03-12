package network.crypta.crypt;

import java.security.interfaces.ECPublicKey;
import network.crypta.support.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight ECDH key-agreement context.
 *
 * <p>This class wraps a single {@link ECDH} instance and exposes the minimal API needed by the
 * networking layer to publish the local EC public key and to derive a shared secret (typically used
 * as an HMAC key or fed to a KDF by higher-level protocols). It also records basic usage timing via
 * {@link KeyAgreementSchemeContext#lastUsedTime()}.
 *
 * <p>Threading: updating the {@code lastUsedTime} timestamp is synchronized on {@code this}. All
 * cryptographic operations are delegated to {@link ECDH}.
 *
 * <p>Logging: with debug logging enabled, the active curve is logged. With trace logging enabled,
 * the local/peer public keys and the derived secret are logged in hex for troubleshooting; enable
 * trace only in controlled environments.
 */
public class ECDHLightContext extends KeyAgreementSchemeContext {
  private static final Logger LOG = LoggerFactory.getLogger(ECDHLightContext.class);

  /** Underlying ECDH primitive that holds the key pair and performs key agreement. */
  public final ECDH ecdh;

  /**
   * Returns a simple string representation. Does not include key material.
   *
   * @return a default, implementation-defined string
   */
  @Override
  public String toString() {
    return super.toString();
  }

  /**
   * Creates a new context with a freshly generated key pair for the given curve.
   *
   * @param curve the elliptic curve to use for key generation and agreement
   */
  public ECDHLightContext(ECDH.Curves curve) {
    this.ecdh = new ECDH(curve);
    this.lastUsedTime = System.currentTimeMillis();
  }

  /**
   * Returns this context's EC public key.
   *
   * @return the local {@link ECPublicKey}; callers may transmit it to a peer
   */
  public ECPublicKey getPublicKey() {
    return ecdh.getPublicKey();
  }

  /**
   * Derives the raw ECDH shared secret with the given peer key.
   *
   * <p>This method updates {@link #lastUsedTime} and delegates the computation to {@link
   * ECDH#getAgreedSecret(ECPublicKey)}. The returned value is the unprocessed shared secret;
   * callers typically feed it into a KDF or use it as an HMAC key as required by higher-level
   * protocols.
   *
   * <p>Performance: computing the shared secret is comparatively expensive; avoid repeated calls
   * when caching is acceptable.
   *
   * @param peerExponential the peer's EC public key; must be compatible with this context's curve
   * @return the raw shared secret, or {@code null} if the agreement fails or the input is invalid
   */
  public byte[] getHMACKey(ECPublicKey peerExponential) {
    synchronized (this) {
      lastUsedTime = System.currentTimeMillis();
    }
    byte[] sharedKey = ecdh.getAgreedSecret(peerExponential);

    if (LOG.isDebugEnabled()) {
      LOG.debug("Curve in use: {}", ecdh.curve);
      if (LOG.isTraceEnabled()) {
        LOG.debug("My exponential: {}", HexUtil.bytesToHex(ecdh.getPublicKey().getEncoded()));
        LOG.debug("Peer's exponential: {}", HexUtil.bytesToHex(peerExponential.getEncoded()));
        LOG.trace("SharedSecret = {}", HexUtil.bytesToHex(sharedKey));
      }
    }

    return sharedKey;
  }

  /**
   * Returns the public key encoded for network transmission.
   *
   * <p>The exact encoding is defined by {@link ECDH#getPublicKeyNetworkFormat()} for the active
   * curve.
   *
   * @return encoded public key bytes suitable for sending on the wire
   */
  @Override
  public byte[] getPublicKeyNetworkFormat() {
    return ecdh.getPublicKeyNetworkFormat();
  }
}

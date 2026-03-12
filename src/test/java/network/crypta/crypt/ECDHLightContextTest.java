package network.crypta.crypt;

import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ECDHLightContextTest {

  @ParameterizedTest
  @EnumSource(ECDH.Curves.class)
  @DisplayName("constructor initializes keys and times for each curve")
  void constructor_whenInvoked_expectPublicKeyAndTimesInitialized(ECDH.Curves curve) {
    ECDHLightContext ctx = new ECDHLightContext(curve);

    assertAll(
        () -> assertNotNull(ctx.getPublicKey(), "Public key must be initialized"),
        () -> assertTrue(ctx.lastUsedTime() >= ctx.lifetime, "lastUsedTime should be >= lifetime"));
  }

  @ParameterizedTest
  @EnumSource(ECDH.Curves.class)
  @DisplayName("agreed secret is equal on both sides and has expected length")
  void getHMACKey_withValidPeerKey_returnsSharedSecretAndUpdatesTime(ECDH.Curves curve) {
    ECDHLightContext alice = new ECDHLightContext(curve);
    ECDHLightContext bob = new ECDHLightContext(curve);

    // Drive determinism for assertions on time by setting baseline explicitly.
    alice.lastUsedTime = 0L;
    bob.lastUsedTime = 0L;

    byte[] secretAB = alice.getHMACKey(bob.getPublicKey());
    byte[] secretBA = bob.getHMACKey(alice.getPublicKey());

    assertAll(
        () -> assertNotNull(secretAB, "Alice's derived secret should not be null"),
        () -> assertArrayEquals(secretAB, secretBA, "Both parties must derive the same secret"),
        () ->
            assertEquals(
                curve.derivedSecretSize,
                secretAB.length,
                "Raw ECDH secret length should match curve expectation"),
        () -> assertTrue(alice.lastUsedTime() > 0L, "Alice lastUsedTime must be updated"),
        () -> assertTrue(bob.lastUsedTime() > 0L, "Bob lastUsedTime must be updated"));
  }

  @Test
  @DisplayName(
      "null peer key either throws NPE (trace logging) or returns null; lastUsedTime updated")
  void getHMACKey_whenPeerIsNull_returnsNullOrThrowsAndUpdatesTime() {
    ECDHLightContext ctx = new ECDHLightContext(ECDH.Curves.P256);
    ctx.lastUsedTime = 0L;

    byte[] secret = null;
    Exception thrown = null;
    try {
      secret = ctx.getHMACKey(null);
    } catch (Exception e) {
      thrown = e;
    }

    final Exception finalThrown = thrown;
    final byte[] finalSecret = secret;
    assertAll(
        () ->
            assertTrue(
                finalThrown == null || finalThrown instanceof NullPointerException,
                "Either no exception or NullPointerException is expected with null peer"),
        () -> {
          if (finalThrown == null) {
            assertNull(finalSecret, "Derived secret must be null for null peer key");
          }
        },
        () -> assertTrue(ctx.lastUsedTime() > 0L, "lastUsedTime must be updated on call"));
  }

  @Test
  @DisplayName(
      "mismatched curves either throw NPE (trace logging) or return null; lastUsedTime updated")
  void getHMACKey_whenCurveMismatches_returnsNullOrThrowsAndUpdatesTime() {
    ECDHLightContext p256 = new ECDHLightContext(ECDH.Curves.P256);
    ECDHLightContext p384 = new ECDHLightContext(ECDH.Curves.P384);
    p256.lastUsedTime = 0L;
    p384.lastUsedTime = 0L;

    byte[] s1 = null;
    byte[] s2 = null;
    Exception t1 = null;
    Exception t2 = null;
    try {
      s1 = p256.getHMACKey(p384.getPublicKey());
    } catch (Exception e) {
      t1 = e;
    }
    try {
      s2 = p384.getHMACKey(p256.getPublicKey());
    } catch (Exception e) {
      t2 = e;
    }

    final Exception ft1 = t1;
    final Exception ft2 = t2;
    final byte[] fs1 = s1;
    final byte[] fs2 = s2;
    assertAll(
        () -> {
          if (ft1 == null) {
            assertNull(fs1, "Secret must be null when curves mismatch (P256 vs P384)");
          } else {
            assertInstanceOf(NullPointerException.class, ft1, "Expected NPE under trace logging");
          }
        },
        () -> {
          if (ft2 == null) {
            assertNull(fs2, "Secret must be null when curves mismatch (P384 vs P256)");
          } else {
            assertInstanceOf(NullPointerException.class, ft2, "Expected NPE under trace logging");
          }
        },
        () -> assertTrue(p256.lastUsedTime() > 0L, "P256 context time should update"),
        () -> assertTrue(p384.lastUsedTime() > 0L, "P384 context time should update"));
  }

  @ParameterizedTest
  @EnumSource(ECDH.Curves.class)
  @DisplayName("public key is EC/X.509 and network format bytes are sane")
  void publicKeyAndNetworkFormat_whenRequested_expectValidValues(ECDH.Curves curve) {
    ECDHLightContext ctx = new ECDHLightContext(curve);
    ECPublicKey pub = ctx.getPublicKey();
    byte[] networkBytes = ctx.getPublicKeyNetworkFormat();

    assertAll(
        () -> assertEquals("EC", pub.getAlgorithm(), "Public key algorithm should be EC"),
        () -> assertEquals("X.509", pub.getFormat(), "Public key format should be X.509"),
        () -> assertNotNull(networkBytes, "Network format bytes must not be null"),
        () -> assertTrue(networkBytes.length > 0, "Network bytes must be non-empty"),
        () ->
            assertTrue(
                networkBytes.length <= curve.modulusSize,
                "Encoded pubkey length must be <= curve modulus size"),
        () ->
            assertArrayEquals(
                ctx.ecdh.getPublicKeyNetworkFormat(),
                networkBytes,
                "Context must delegate to underlying ECDH for network format"));
  }

  @Test
  @DisplayName("toString contains class name (sanity check)")
  void toString_whenCalled_containsClassName() {
    ECDHLightContext ctx = new ECDHLightContext(ECDH.Curves.P256);
    String s = ctx.toString();
    assertTrue(s.contains("ECDHLightContext"));
  }
}

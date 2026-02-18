package network.crypta.crypt;

import java.security.PublicKey;
import java.security.Security;
import java.util.EnumSet;
import java.util.stream.Stream;
import network.crypta.crypt.ECDH.Curves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ECDHTest {

  @BeforeAll
  void addBouncyCastleProvider() {
    // Ensure BC is available regardless of environment defaults
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @ParameterizedTest
  @EnumSource(Curves.class)
  @DisplayName("ECDH agreed secret matches and has expected length per curve")
  void getAgreedSecret_whenPeersUseSameCurve_secretsMatchAndLengthMatches(Curves curve) {
    // Arrange
    ECDH alice = new ECDH(curve);
    ECDH bob = new ECDH(curve);

    // Act
    byte[] aliceSecret = alice.getAgreedSecret(bob.getPublicKey());
    byte[] bobSecret = bob.getAgreedSecret(alice.getPublicKey());

    // Assert
    assertNotNull(aliceSecret);
    assertNotNull(bobSecret);
    assertArrayEquals(aliceSecret, bobSecret);
    assertEquals(curve.derivedSecretSize, aliceSecret.length);
    assertEquals(curve.derivedSecretSize, bobSecret.length);
  }

  @ParameterizedTest
  @EnumSource(Curves.class)
  void getPublicKey_whenRequested_returnsDistinctNonNullWithExpectedEncodingSize(Curves curve) {
    // Arrange
    ECDH alice = new ECDH(curve);
    ECDH bob = new ECDH(curve);

    // Act
    PublicKey aliceP = alice.getPublicKey();
    PublicKey bobP = bob.getPublicKey();

    // Assert
    assertNotNull(aliceP);
    assertNotNull(bobP);
    assertNotSame(aliceP, bobP);
    assertEquals(curve.modulusSize, aliceP.getEncoded().length);
    assertEquals(curve.modulusSize, bobP.getEncoded().length);
  }

  @ParameterizedTest
  @EnumSource(Curves.class)
  void getPublicKeyNetworkFormat_whenNormal_returnsEncodedBytes(Curves curve) {
    // Arrange
    ECDH alice = new ECDH(curve);

    // Act
    byte[] network = alice.getPublicKeyNetworkFormat();

    // Assert
    assertArrayEquals(alice.getPublicKey().getEncoded(), network);
    assertEquals(curve.modulusSize, network.length);
  }

  @Test
  void getAgreedSecret_whenNullPublicKey_returnsNull() {
    // Arrange
    ECDH alice = new ECDH(Curves.P256);

    // Act
    byte[] s = alice.getAgreedSecret(null);

    // Assert
    assertNull(s);
  }

  @Test
  void getPublicKey_whenNullBytes_throwsNPE() {
    // Act + Assert
    assertThrows(NullPointerException.class, () -> ECDH.getPublicKey(null, Curves.P256));
  }

  @Test
  void getPublicKey_whenEmptyBytes_returnsNull() {
    // Arrange
    byte[] empty = new byte[0];

    // Act
    var key = ECDH.getPublicKey(empty, Curves.P256);

    // Assert
    assertNull(key);
  }

  static Stream<Arguments> mismatchedCurves() {
    // All ordered pairs of distinct curves
    var curves = EnumSet.allOf(Curves.class).toArray(new Curves[0]);
    Stream.Builder<Arguments> b = Stream.builder();
    for (Curves a : curves) {
      for (Curves c : curves) {
        if (a != c) b.add(Arguments.of(a, c));
      }
    }
    return b.build();
  }

  @ParameterizedTest
  @MethodSource("mismatchedCurves")
  void getAgreedSecret_whenCurvesDiffer_returnsNull(Curves a, Curves b) {
    // Arrange
    ECDH alice = new ECDH(a);
    ECDH bob = new ECDH(b);

    // Act
    byte[] s1 = alice.getAgreedSecret(bob.getPublicKey());
    byte[] s2 = bob.getAgreedSecret(alice.getPublicKey());

    // Assert
    assertNull(s1);
    assertNull(s2);
  }

  @Test
  void blockingInit_whenCalledTwice_doesNotThrow() {
    // Act + Assert
    assertDoesNotThrow(
        () -> {
          ECDH.blockingInit();
          ECDH.blockingInit();
        });
  }

  @Test
  void getPublicKeyNetworkFormat_whenEncodedTooLong_throwsIllegalStateException() {
    // Arrange
    ECDH ecdh = new ECDH(Curves.P256);
    ECDH spy = Mockito.spy(ecdh);
    // Mock a public key with encoding larger than expected
    PublicKey fake =
        Mockito.mock(
            PublicKey.class,
            Mockito.withSettings().extraInterfaces(java.security.interfaces.ECPublicKey.class));
    byte[] tooLong = new byte[Curves.P256.modulusSize + 5];
    Mockito.when(fake.getEncoded()).thenReturn(tooLong);
    Mockito.doReturn(fake).when(spy).getPublicKey();

    // Act + Assert
    assertThrows(IllegalStateException.class, spy::getPublicKeyNetworkFormat);
  }

  @Test
  void
      getPublicKeyNetworkFormat_whenEncodedTooShort_returnsUnpaddedBytesDueToCurrentImplementation() {
    // Arrange
    ECDH ecdh = new ECDH(Curves.P256);
    ECDH spy = Mockito.spy(ecdh);
    PublicKey fake =
        Mockito.mock(
            PublicKey.class,
            Mockito.withSettings().extraInterfaces(java.security.interfaces.ECPublicKey.class));
    byte[] tooShort = new byte[Curves.P256.modulusSize - 7];
    Mockito.when(fake.getEncoded()).thenReturn(tooShort);
    Mockito.doReturn(fake).when(spy).getPublicKey();

    // Act
    byte[] network = spy.getPublicKeyNetworkFormat();

    // Assert
    // Current implementation warns and returns original, unpadded bytes
    assertArrayEquals(tooShort, network);
    assertEquals(tooShort.length, network.length);
  }

  @ParameterizedTest
  @EnumSource(Curves.class)
  void getPublicKey_roundTripEncoding_yieldsEquivalentKey(Curves curve) {
    // Arrange
    ECDH alice = new ECDH(curve);
    byte[] encoded = alice.getPublicKey().getEncoded();

    // Act
    var reconstructed = ECDH.getPublicKey(encoded, curve);

    // Assert
    assertNotNull(reconstructed);
    assertArrayEquals(encoded, reconstructed.getEncoded());
  }
}

package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;
import network.crypta.support.Base64;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"java:S100", "java:S2245"})
class DSAPrivateKeyTest {

  private static final DSAGroup GROUP = Global.DSAgroupBigA;

  @Test
  void constructor_whenNonPositiveOrTooLarge_expectIllegalArgument() {
    BigInteger q = GROUP.getQ();
    BigInteger minusOne = BigInteger.valueOf(-1);
    BigInteger qPlusOne = q.add(BigInteger.ONE);

    assertThrows(IllegalArgumentException.class, () -> new DSAPrivateKey(BigInteger.ZERO, GROUP));
    assertThrows(IllegalArgumentException.class, () -> new DSAPrivateKey(minusOne, GROUP));
    assertThrows(IllegalArgumentException.class, () -> new DSAPrivateKey(q, GROUP));
    assertThrows(IllegalArgumentException.class, () -> new DSAPrivateKey(qPlusOne, GROUP));
  }

  @Test
  void constructor_whenBoundaryValues_expectAcceptedAndKeyType() {
    BigInteger q = GROUP.getQ();
    DSAPrivateKey xIsOne = new DSAPrivateKey(BigInteger.ONE, GROUP);
    DSAPrivateKey xIsQMinus1 = new DSAPrivateKey(q.subtract(BigInteger.ONE), GROUP);

    assertEquals(BigInteger.ONE, xIsOne.getX());
    assertEquals(q.subtract(BigInteger.ONE), xIsQMinus1.getX());
    assertEquals("DSA.s", xIsOne.keyType());
  }

  @Test
  void randomConstructor_withSeededRandom_expectDeterministicInRange() {
    Random seeded = new Random(123456789L);
    DSAPrivateKey generated = new DSAPrivateKey(GROUP, seeded);

    // Reproduce the same selection logic to compute the expected value deterministically.
    Random replay = new Random(123456789L);
    BigInteger expected;
    do {
      expected = new BigInteger(256, replay);
    } while (expected.compareTo(GROUP.getQ()) >= 0 || expected.compareTo(BigInteger.ZERO) <= 0);

    BigInteger genX = generated.getX();
    assertEquals(expected, genX);
    // Guard against theoretical null to satisfy static analysis before dereference.
    org.junit.jupiter.api.Assertions.assertNotNull(genX);
    assertEquals(1, genX.signum());
    assertTrue(genX.compareTo(GROUP.getQ()) < 0);
  }

  @Test
  void read_whenValidMPI_expectParsedKeyWithSameX() throws IOException {
    BigInteger x = BigInteger.valueOf(42);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    Util.writeMPI(x, bos);
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());

    CryptoKey parsed = DSAPrivateKey.read(bis, GROUP);
    DSAPrivateKey asDSA = assertInstanceOf(DSAPrivateKey.class, parsed);
    assertEquals(x, asDSA.getX());
  }

  @Test
  void read_whenZeroMPI_expectIllegalArgumentFromConstructor() throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    Util.writeMPI(BigInteger.ZERO, bos);
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
    assertThrows(IllegalArgumentException.class, () -> DSAPrivateKey.read(bis, GROUP));
  }

  @Test
  void asBytes_whenCalled_expectMPIEncoding() {
    BigInteger x = new BigInteger("1234", 16);
    DSAPrivateKey key = new DSAPrivateKey(x, GROUP);
    assertArrayEquals(Util.mpiBytes(x), key.asBytes());
  }

  @Test
  void fingerprint_whenComputed_matchesSHA1OfMPI() {
    BigInteger x = new BigInteger("a5", 16);
    DSAPrivateKey key = new DSAPrivateKey(x, GROUP);

    MessageDigest sha1 = HashType.SHA1.get();
    sha1.update(Util.mpiBytes(x));
    byte[] expected = sha1.digest();

    assertArrayEquals(expected, key.fingerprint());
  }

  @Test
  @DisplayName("toLongString renders x in hex via HexUtil.biToHex")
  void toLongString_whenCalled_expectHexOfX() {
    BigInteger x = new BigInteger("ff", 16); // ensure leading sign byte in toByteArray()
    DSAPrivateKey key = new DSAPrivateKey(x, GROUP);
    assertEquals("x=" + HexUtil.biToHex(x), key.toLongString());
  }

  @Test
  void asFieldSet_andCreate_roundTrip() throws IllegalBase64Exception {
    BigInteger x = new BigInteger("ff", 16); // triggers a leading 0x00 in toByteArray()
    DSAPrivateKey original = new DSAPrivateKey(x, GROUP);

    SimpleFieldSet fs = original.asFieldSet();

    // Stored value is Base64 of BigInteger#toByteArray() bytes.
    assertArrayEquals(x.toByteArray(), Base64.decode(fs.get("x")));

    DSAPrivateKey parsed = DSAPrivateKey.create(fs, GROUP);
    assertEquals(x, parsed.getX());
  }

  @Test
  void create_whenMissingXField_expectNullPointerException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    // No "x" entry present
    assertThrows(NullPointerException.class, () -> DSAPrivateKey.create(fs, GROUP));
  }

  @Test
  void create_whenBitLengthGreaterThan512_expectIllegalBase64Exception() {
    // Construct x with bitLength = 513 (2^512)
    BigInteger tooLarge = BigInteger.ONE.shiftLeft(512);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("x", Base64.encode(tooLarge.toByteArray()));
    assertThrows(IllegalBase64Exception.class, () -> DSAPrivateKey.create(fs, GROUP));
  }
}

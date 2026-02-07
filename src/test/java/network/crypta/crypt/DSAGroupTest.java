package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.stream.Stream;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class DSAGroupTest {

  private static DSAGroup newGroup(BigInteger p, BigInteger q, BigInteger g) {
    return new DSAGroup(p, q, g);
  }

  static Stream<Arguments> nonPositiveTriples() {
    BigInteger one = BigInteger.ONE;
    return Stream.of(
        Arguments.of(BigInteger.ZERO, one, one),
        Arguments.of(one, BigInteger.ZERO, one),
        Arguments.of(one, one, BigInteger.ZERO));
  }

  @ParameterizedTest
  @MethodSource("nonPositiveTriples")
  void constructor_whenNonPositiveParams_expectIllegalArgument(
      BigInteger p, BigInteger q, BigInteger g) {
    assertThrows(IllegalArgumentException.class, () -> newGroup(p, q, g));
  }

  @Test
  void keyType_whenSmallP_expectBitLengthReflected() {
    // p has bitLength 8, so keyType should end with "-8".
    DSAGroup grp = newGroup(new BigInteger("ff", 16), BigInteger.valueOf(3), BigInteger.TWO);
    assertEquals("DSA.g-8", grp.keyType());
  }

  @Test
  void equalsAndHashCode_whenSameValues_expectEqualAndHashMatch() {
    BigInteger p = new BigInteger("123456", 16);
    BigInteger q = new BigInteger("789", 16);
    BigInteger g = new BigInteger("abc", 16);
    DSAGroup a = newGroup(p, q, g);
    DSAGroup b = newGroup(p, q, g);

    // equals(Object)
    assertEquals(a, b);
    // equals(DSAGroup)
    assertTrue(a.equals(b));
    // hashCode contract
    assertEquals(a.hashCode(), b.hashCode());

    // Not equal to a different g
    DSAGroup c = newGroup(p, q, g.add(BigInteger.ONE));
    assertNotEquals(a, c);
  }

  @Test
  void asBytes_whenCalled_expectConcatenatedMPI() {
    BigInteger p = new BigInteger("10", 16); // 16
    BigInteger q = new BigInteger("1ff", 16); // 511
    BigInteger g = new BigInteger("2", 16); // 2
    DSAGroup grp = newGroup(p, q, g);

    byte[] expected = concat(Util.mpiBytes(p), Util.mpiBytes(q), Util.mpiBytes(g));
    assertArrayEquals(expected, grp.asBytes());
  }

  @Test
  void fingerprint_whenComputed_matchesSHA1OfMPI() {
    BigInteger p = new BigInteger("a5", 16);
    BigInteger q = new BigInteger("b6", 16);
    BigInteger g = new BigInteger("c7", 16);
    DSAGroup grp = newGroup(p, q, g);

    MessageDigest sha1 = HashType.SHA1.get();
    sha1.update(Util.mpiBytes(p));
    sha1.update(Util.mpiBytes(q));
    sha1.update(Util.mpiBytes(g));
    byte[] expected = sha1.digest();

    assertArrayEquals(expected, grp.fingerprint());
  }

  @Test
  void asFieldSet_andCreate_roundTrip() throws IllegalBase64Exception, FSParseException {
    BigInteger p = new BigInteger("7fffff", 16); // ensure a sign byte is present in toByteArray()
    BigInteger q = new BigInteger("f", 16);
    BigInteger g = new BigInteger("100", 16);
    DSAGroup original = newGroup(p, q, g);

    SimpleFieldSet fs = original.asFieldSet();

    // Values are Base64 of the two's-complement bytes from BigInteger#toByteArray().
    assertArrayEquals(p.toByteArray(), Base64.decode(fs.get("p")));
    assertArrayEquals(q.toByteArray(), Base64.decode(fs.get("q")));
    assertArrayEquals(g.toByteArray(), Base64.decode(fs.get("g")));

    DSAGroup reparsed = DSAGroup.create(fs);
    assertEquals(original, reparsed);
    assertNotSame(original, reparsed); // create() does not preserve identity for non-singletons
  }

  @Test
  void create_whenMissingFields_expectFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("p", Base64.encode(BigInteger.TWO.toByteArray()));
    // omit q and g
    assertThrows(FSParseException.class, () -> DSAGroup.create(fs));
  }

  @Test
  void create_whenInvalidBase64_expectIllegalBase64Exception() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("p", "@@@");
    fs.putSingle("q", Base64.encode(BigInteger.ONE.toByteArray()));
    fs.putSingle("g", Base64.encode(BigInteger.TWO.toByteArray()));
    assertThrows(IllegalBase64Exception.class, () -> DSAGroup.create(fs));
  }

  @Test
  void create_withBigAValues_returnsCanonical() throws IllegalBase64Exception, FSParseException {
    DSAGroup bigA = Global.DSAgroupBigA;
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("p", Base64.encode(bigA.getP().toByteArray()));
    fs.putSingle("q", Base64.encode(bigA.getQ().toByteArray()));
    fs.putSingle("g", Base64.encode(bigA.getG().toByteArray()));

    DSAGroup created = DSAGroup.create(fs);
    assertSame(bigA, created, "Expected canonical Global.DSAgroupBigA instance");
  }

  @Test
  void read_withValidMPIForBigA_returnsCanonicalInstance() throws Exception {
    DSAGroup bigA = Global.DSAgroupBigA;
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    Util.writeMPI(bigA.getP(), bos);
    Util.writeMPI(bigA.getQ(), bos);
    Util.writeMPI(bigA.getG(), bos);
    ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());

    CryptoKey parsed = DSAGroup.readKey(bis);
    assertSame(bigA, parsed, "Expected canonical Global.DSAgroupBigA instance");
  }

  @Test
  void read_withZeroValues_throwsCryptFormatException() {
    // Encode p=q=g=0 as MPI. Constructor rejects signum != 1, so read() wraps it.
    byte[] mpiZero = Util.mpiBytes(BigInteger.ZERO);
    byte[] threeZeros = concat(mpiZero, mpiZero, mpiZero);
    ByteArrayInputStream bis = new ByteArrayInputStream(threeZeros);
    assertThrows(CryptFormatException.class, () -> DSAGroup.readKey(bis));
  }

  @Test
  @DisplayName("toString overrides for canonical group and long string formatting")
  void toString_and_toLongString_behavior() {
    // Non-singleton formatting
    BigInteger p = new BigInteger("ff", 16); // 255 -> two's complement includes leading 00
    BigInteger q = new BigInteger("1", 16);
    BigInteger g = new BigInteger("7", 16);
    DSAGroup grp = newGroup(p, q, g);

    String longStr = grp.toLongString();
    assertEquals(
        "p=" + HexUtil.biToHex(p) + ", q=" + HexUtil.biToHex(q) + ", g=" + HexUtil.biToHex(g),
        longStr);

    // Canonical singleton uses a special toString/toLongString
    assertEquals("Global.DSAgroupBigA", Global.DSAgroupBigA.toString());
    assertEquals("Global.DSAgroupBigA", Global.DSAgroupBigA.toLongString());
  }

  @Test
  void cloneKey_whenNonCanonical_returnsEqualButDifferentInstance() {
    DSAGroup grp = newGroup(BigInteger.valueOf(23), BigInteger.valueOf(5), BigInteger.valueOf(4));
    DSAGroup cloned = grp.cloneKey();
    assertEquals(grp, cloned);
    assertNotSame(grp, cloned);
  }

  @Test
  void cloneKey_whenCanonical_returnsSameInstance() {
    DSAGroup bigA = Global.DSAgroupBigA;
    DSAGroup cloned = bigA.cloneKey();
    assertSame(bigA, cloned);
  }

  private static byte[] concat(byte[] a, byte[] b, byte[] c) {
    byte[] out = new byte[a.length + b.length + c.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    System.arraycopy(c, 0, out, a.length + b.length, c.length);
    return out;
  }
}

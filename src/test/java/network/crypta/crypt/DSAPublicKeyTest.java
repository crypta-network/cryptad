package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DSAPublicKeyTest {

  private static final DSAGroup GROUP = Global.DSAgroupBigA;

  @Test
  void constructor_withValidY_setsFieldsAndNormalizesGroup() {
    BigInteger y = BigInteger.TWO;
    DSAPublicKey key = new DSAPublicKey(GROUP, y);

    assertEquals(y, key.getY());
    assertSame(GROUP, key.getGroup());
    assertEquals("DSA.p", key.keyType());
    assertEquals(GROUP.getP(), key.getP());
    assertEquals(GROUP.getQ(), key.getQ());
    assertEquals(GROUP.getG(), key.getG());
  }

  @Test
  void constructor_withZeroY_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new DSAPublicKey(GROUP, BigInteger.ZERO));
  }

  @Test
  void constructor_withYGreaterThanP_throwsIllegalArgumentException() {
    DSAGroup small =
        new DSAGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(5));
    BigInteger p = small.getP();
    assertNotNull(p);
    BigInteger y = p.add(BigInteger.ONE);
    assertThrows(IllegalArgumentException.class, () -> new DSAPublicKey(small, y));
  }

  @Test
  void stringCtor_whenYGreaterThanP_doesNotValidateRangeYet() {
    DSAGroup small =
        new DSAGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(5));
    BigInteger p = small.getP();
    assertNotNull(p);
    BigInteger y = p.add(BigInteger.ONE);
    DSAPublicKey key = new DSAPublicKey(small, y.toString(16));
    assertEquals(y, key.getY());
    assertSame(small, key.getGroup());
  }

  @Test
  void asBytes_roundTrip_throughByteArrayCtor_preservesEquality()
      throws IOException, CryptFormatException {
    DSAPublicKey k1 = new DSAPublicKey(GROUP, BigInteger.TWO);
    byte[] encoded = k1.asBytes();
    DSAPublicKey k2 = new DSAPublicKey(encoded);

    assertTrue(k1.equals(k2)); // typed equals
    assertEquals(k1, k2); // Object.equals
    assertEquals(k1.hashCode(), k2.hashCode());
  }

  @Test
  void read_staticMethod_readsFromStream() throws IOException, CryptFormatException {
    DSAPublicKey original = new DSAPublicKey(GROUP, BigInteger.valueOf(3));
    ByteArrayInputStream in = new ByteArrayInputStream(original.asBytes());
    CryptoKey parsed = DSAPublicKey.readKey(in);
    assertInstanceOf(DSAPublicKey.class, parsed);
    assertTrue(original.equals((DSAPublicKey) parsed));
  }

  @Test
  void create_static_withInvalidBytes_throwsCryptFormatException() {
    byte[] invalid = new byte[] {1, 2, 3}; // truncated; not enough for even one MPI
    assertThrows(CryptFormatException.class, () -> DSAPublicKey.create(invalid));
  }

  @Test
  void asBytesHash_returnsSha256OfAsBytes() {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(5));
    byte[] expected = SHA256.digest(key.asBytes());
    assertArrayEquals(expected, key.asBytesHash());
  }

  @Test
  void asPaddedBytes_whenShort_padsWithZerosAndKeepsPrefix() {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(7));
    byte[] raw = key.asBytes();
    assertTrue(raw.length < DSAPublicKey.PADDED_SIZE);
    byte[] padded = key.asPaddedBytes();
    assertEquals(DSAPublicKey.PADDED_SIZE, padded.length);
    assertArrayEquals(raw, Arrays.copyOf(padded, raw.length));
  }

  @Test
  void asPaddedBytes_whenTooLarge_throwsError() {
    DSAGroup hugeBytesGroup =
        new DSAGroup(BigInteger.valueOf(97), BigInteger.valueOf(13), BigInteger.valueOf(5)) {
          @Override
          public byte[] asBytes() {
            return new byte[DSAPublicKey.PADDED_SIZE + 64];
          }
        };
    DSAPublicKey key = new DSAPublicKey(hugeBytesGroup, BigInteger.TWO);
    assertThrows(Error.class, key::asPaddedBytes);
  }

  @Test
  void fingerprint_whenCalledTwice_returnsSameCachedInstance() {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(9));
    byte[] fp1 = key.fingerprint();
    byte[] fp2 = key.fingerprint();
    assertNotNull(fp1);
    assertSame(fp1, fp2); // cached instance should be reused
  }

  @Test
  void equalsAndHashCode_whenSameValues_consistent() {
    BigInteger y = BigInteger.valueOf(10);
    DSAPublicKey a = new DSAPublicKey(GROUP, y);
    DSAPublicKey b = new DSAPublicKey(GROUP, y);
    assertTrue(a.equals(b));
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentGroup_returnsFalse() {
    BigInteger y = BigInteger.valueOf(11);
    DSAPublicKey a = new DSAPublicKey(GROUP, y);
    DSAGroup otherGroup =
        new DSAGroup(BigInteger.valueOf(101), BigInteger.valueOf(19), BigInteger.valueOf(6));
    DSAPublicKey b = new DSAPublicKey(otherGroup, y);
    assertFalse(a.equals(b));
  }

  @Test
  void equalsObject_whenNullOrDifferentType_returnsFalse() {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(12));
    // Prefer assertNotEquals to avoid static analyzer warning about equals(null)
    assertNotEquals(null, key);
    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals("not-a-key", key);
  }

  @Test
  void compareTo_whenDifferentY_ordersByMagnitude() {
    DSAPublicKey small = new DSAPublicKey(GROUP, BigInteger.valueOf(2));
    DSAPublicKey large = new DSAPublicKey(GROUP, BigInteger.valueOf(3));
    assertTrue(small.compareTo(large) < 0);
    assertTrue(large.compareTo(small) > 0);
    assertEquals(-1, small.compareTo("not-a-key"));
  }

  @Test
  void asFieldSet_roundTrip_create_returnsEqualKey() throws FSParseException {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(14));
    SimpleFieldSet fs = key.asFieldSet();
    DSAPublicKey parsed = DSAPublicKey.create(fs, GROUP);
    assertEquals(key.getY(), parsed.getY());
    assertEquals(key.getGroup(), parsed.getGroup());
  }

  @Test
  void create_fromFieldSet_withInvalidBase64_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("y", "not base64!!");
    assertThrows(FSParseException.class, () -> DSAPublicKey.create(fs, GROUP));
  }

  @Test
  void getFullKey_and_getRoutingKey_equal_asBytesHash() {
    DSAPublicKey key = new DSAPublicKey(GROUP, BigInteger.valueOf(16));
    byte[] hash = key.asBytesHash();
    assertArrayEquals(hash, key.getFullKey());
    assertArrayEquals(hash, key.getRoutingKey());
  }

  @Test
  void keyId_returnsLower32BitsOfY() {
    BigInteger y = new BigInteger("12345678901234567890");
    DSAPublicKey key = new DSAPublicKey(GROUP, y);
    assertEquals(y.intValue(), key.keyId());
  }

  @Test
  void toLongString_containsHexRepresentationOfY() {
    BigInteger y = new BigInteger("42");
    DSAPublicKey key = new DSAPublicKey(GROUP, y);
    String s = key.toLongString();
    assertTrue(s.startsWith("y="));
    // Basic sanity: the hex of 42 is 2a, so the string should contain it.
    assertTrue(s.contains("2a"));
  }
}

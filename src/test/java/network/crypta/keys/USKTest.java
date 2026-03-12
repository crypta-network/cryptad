package network.crypta.keys;

import java.net.MalformedURLException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKTest {

  private static final String SITE_NAME = "site";
  private static final String SITE_MYSITE = "mysite";

  private static byte[] bytes(int len, int start) {
    byte[] b = new byte[len];
    for (int i = 0; i < len; i++) b[i] = (byte) (start + i);
    return b;
  }

  private static USK newUsk(String site, long edition) throws MalformedURLException {
    byte[] pubKeyHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0);
    byte[] cryptoKey = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 32);
    byte[] extra = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    return new USK(pubKeyHash, cryptoKey, extra, site, edition);
  }

  // Reflection helper for the private static method USK.hasEditionSuffix(String)
  private static boolean hasEditionSuffix(String name) {
    try {
      var m = USK.class.getDeclaredMethod("hasEditionSuffix", String.class);
      m.setAccessible(true);
      return (Boolean) m.invoke(null, name);
    } catch (ReflectiveOperationException e) {
      throw linkageError("Unable to invoke hasEditionSuffix via reflection", e);
    }
  }

  private static LinkageError linkageError(String message, ReflectiveOperationException e) {
    LinkageError error = new LinkageError(message);
    error.initCause(e);
    return error;
  }

  @Test
  void constructor_whenExtraNull_throwsMalformedURLException() {
    byte[] pubKeyHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 1);
    byte[] cryptoKey = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 2);
    assertThrows(
        MalformedURLException.class, () -> new USK(pubKeyHash, cryptoKey, null, "site", 1L));
  }

  @Test
  void constructor_whenPubKeyHashNull_throwsMalformedURLException() {
    byte[] cryptoKey = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 2);
    byte[] extra = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    assertThrows(MalformedURLException.class, () -> new USK(null, cryptoKey, extra, "site", 1L));
  }

  @Test
  void constructor_whenCryptoKeyNull_throwsMalformedURLException() {
    byte[] pubKeyHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 1);
    byte[] extra = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    assertThrows(MalformedURLException.class, () -> new USK(pubKeyHash, null, extra, "site", 1L));
  }

  @Test
  void constructor_whenLengthsWrong_throwsMalformedURLException() {
    byte[] pubKeyHashWrong = bytes(NodeSSK.PUBKEY_HASH_SIZE - 1, 1);
    byte[] cryptoKeyWrong = bytes(ClientSSK.CRYPTO_KEY_LENGTH - 1, 2);
    byte[] extra = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    assertThrows(
        MalformedURLException.class,
        () -> new USK(pubKeyHashWrong, bytes(ClientSSK.CRYPTO_KEY_LENGTH, 3), extra, "s", 1));
    assertThrows(
        MalformedURLException.class,
        () -> new USK(bytes(NodeSSK.PUBKEY_HASH_SIZE, 4), cryptoKeyWrong, extra, "s", 1));
  }

  @Test
  void getURI_whenConstructed_returnsEquivalentUSKUri() throws MalformedURLException {
    String site = SITE_MYSITE;
    long edition = 42L;
    USK usk = newUsk(site, edition);

    FreenetURI uri = usk.getURI();

    assertEquals("USK", uri.getKeyType());
    assertEquals(site, uri.getDocName());
    assertEquals(edition, uri.getSuggestedEdition());
    assertArrayEquals(bytes(NodeSSK.PUBKEY_HASH_SIZE, 0), uri.getRoutingKey());
    assertArrayEquals(bytes(ClientSSK.CRYPTO_KEY_LENGTH, 32), uri.getCryptoKey());
    assertArrayEquals(ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256), uri.getExtra());
  }

  @Test
  void create_whenUriNotUSK_throwsMalformedURLException() {
    byte[] r = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0);
    byte[] c = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 32);
    byte[] e = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    FreenetURI notUsk = new FreenetURI("SSK", "doc", r, c, e);
    assertThrows(MalformedURLException.class, () -> USK.create(notUsk));
  }

  @Test
  void create_whenUriIsUSK_buildsMatchingUSK() throws MalformedURLException {
    byte[] r = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0);
    byte[] c = bytes(ClientSSK.CRYPTO_KEY_LENGTH, 32);
    byte[] e = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    FreenetURI in = new FreenetURI(r, c, e, "siteA", 5L);

    USK usk = USK.create(in);

    assertEquals(in, usk.getURI());
  }

  @Test
  void getSSK_whenGivenVersion_returnsClientSSKWithComposedName() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 9L);
    ClientSSK ssk = usk.getSSK(123L);
    assertEquals("site-123", ssk.docName);
    assertArrayEquals(usk.getURI().getRoutingKey(), ssk.pubKeyHash);
    assertArrayEquals(usk.getURI().getCryptoKey(), ssk.cryptoKey);
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, ssk.cryptoAlgorithm);
  }

  @Test
  void getSSK_whenNoVersion_usesSuggestedEdition() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 17L);
    ClientKey key = usk.getSSK();
    assertInstanceOf(ClientSSK.class, key);
    assertEquals("site-17", ((ClientSSK) key).docName);
  }

  @Test
  void getName_whenGivenVersion_formatsCorrectly() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 1L);
    assertEquals("site-1000", usk.getName(1000L));
  }

  @Test
  void copy_withSameEdition_returnsSameInstance() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 3L);
    assertSame(usk, usk.copy(3L));
  }

  @Test
  void copy_withDifferentEdition_returnsNewUSK() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 3L);
    USK other = usk.copy(4L);
    assertNotSame(usk, other);
    assertTrue(usk.equals(other, false));
    assertNotEquals(usk, other);
  }

  @Test
  void clearCopy_setsEditionToZero() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 99L);
    assertEquals(0L, usk.clearCopy().suggestedEdition);
  }

  @Test
  void copy_defaultCopy_hasSameLogicalContent() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 7L);
    USK copy = usk.copy();
    assertNotSame(usk, copy);
    assertEquals(usk, copy);
    assertEquals(usk.hashCode(), copy.hashCode());
  }

  @Test
  void equals_whenIgnoringVersion_treatsDifferentEditionsAsEqual() throws MalformedURLException {
    USK a = newUsk(SITE_NAME, 1L);
    USK b = newUsk(SITE_NAME, 2L);
    assertNotEquals(a, b);
    assertTrue(a.equals(b, false));
  }

  @Test
  void getBaseSSK_returnsSSKUriWithSiteName() throws MalformedURLException {
    USK usk = newUsk("base", 1L);
    FreenetURI sskBase = usk.getBaseSSK();
    assertEquals("SSK", sskBase.getKeyType());
    assertEquals("base", sskBase.getDocName());
    assertArrayEquals(usk.getURI().getRoutingKey(), sskBase.getRoutingKey());
    assertArrayEquals(usk.getURI().getCryptoKey(), sskBase.getCryptoKey());
    assertArrayEquals(ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256), sskBase.getExtra());
  }

  // ===== hasEditionSuffix tests (merged from USKEditionSuffixTest) =====

  @Test
  void hasEditionSuffix_whenTrailingDigits_returnsTrue() {
    // Arrange
    String name = "foo-12";
    // Act
    boolean result = hasEditionSuffix(name);
    // Assert
    assertTrue(result);
  }

  @Test
  void hasEditionSuffix_whenDigitsBeforeSlash_returnsTrue() {
    // Arrange
    String a = "foo-12/bar";
    String b = "blog-2020/notes";
    // Act
    boolean ra = hasEditionSuffix(a);
    boolean rb = hasEditionSuffix(b);
    // Assert
    assertTrue(ra);
    assertTrue(rb);
  }

  @Test
  void hasEditionSuffix_whenNonMatchingDigitRun_thenLaterDigits_returnsTrue() {
    // Arrange
    String name = "foo-1a-23"; // regression: must keep scanning after "-1a"
    // Act
    boolean result = hasEditionSuffix(name);
    // Assert
    assertTrue(result);
  }

  @Test
  void hasEditionSuffix_whenLetterImmediatelyAfterDigits_returnsFalse() {
    // Arrange
    String a = "foo-12a";
    String b = "foo-0a/bar";
    // Act
    boolean ra = hasEditionSuffix(a);
    boolean rb = hasEditionSuffix(b);
    // Assert
    assertFalse(ra);
    assertFalse(rb);
  }

  @Test
  void hasEditionSuffix_whenNoSuffix_returnsFalse() {
    // Arrange
    String[] names = new String[] {"foo", "-", "foo-", ""};
    // Act & Assert
    for (String n : names) {
      assertFalse(hasEditionSuffix(n), () -> "Expected no suffix for '" + n + "'");
    }
    assertFalse(hasEditionSuffix(null));
  }

  @Test
  void turnMySSKIntoUSK_whenMatchingSSK_convertsAndPreservesMeta() throws MalformedURLException {
    USK usk = newUsk(SITE_MYSITE, 10L);
    byte[] r = usk.getURI().getRoutingKey();
    byte[] c = usk.getURI().getCryptoKey();
    byte[] e = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    String[] meta = new String[] {"dir", "file.txt"};
    FreenetURI ssk = new FreenetURI("SSK", SITE_MYSITE + "-123", meta, r, c, e, 0);

    FreenetURI converted = usk.turnMySSKIntoUSK(ssk);

    assertEquals("USK", converted.getKeyType());
    assertEquals(SITE_MYSITE, converted.getDocName());
    assertEquals(123L, converted.getSuggestedEdition());
    assertArrayEquals(meta, converted.getAllMetaStrings());
    assertArrayEquals(r, converted.getRoutingKey());
    assertArrayEquals(c, converted.getCryptoKey());
  }

  @Test
  void turnMySSKIntoUSK_whenNotOurSSK_returnsOriginal() throws MalformedURLException {
    USK usk = newUsk(SITE_MYSITE, 10L);
    // Different routing key → should not convert
    byte[] r = bytes(NodeSSK.PUBKEY_HASH_SIZE, 99);
    byte[] c = usk.getURI().getCryptoKey();
    byte[] e = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    FreenetURI ssk = new FreenetURI("SSK", SITE_MYSITE + "-1", r, c, e);
    assertSame(ssk, usk.turnMySSKIntoUSK(ssk));
  }

  @Test
  void turnMySSKIntoUSK_whenDocHasLeadingZeros_returnsOriginal() throws MalformedURLException {
    USK usk = newUsk(SITE_MYSITE, 10L);
    byte[] r = usk.getURI().getRoutingKey();
    byte[] c = usk.getURI().getCryptoKey();
    byte[] e = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    FreenetURI ssk = new FreenetURI("SSK", SITE_MYSITE + "-0012", r, c, e);
    assertSame(ssk, usk.turnMySSKIntoUSK(ssk));
  }

  @Test
  void compareTo_ordersByFields() throws MalformedURLException {
    USK a = newUsk("a", 1L);
    USK b = newUsk("a", 2L);
    USK c = newUsk("b", 0L);
    assertTrue(a.compareTo(b) < 0); // edition differs
    assertTrue(b.compareTo(c) < 0); // siteName differs
    // Use a logically equal copy to avoid self-comparison code smell
    assertEquals(0, a.compareTo(a.copy()));
  }

  @Test
  void fastComparator_consistentWithCompareTo() throws MalformedURLException {
    USK a = newUsk("x", 100L);
    USK b = newUsk("y", 50L);
    int cmp = a.compareTo(b);
    int fast = USK.FAST_COMPARATOR.compare(a, b);
    assertEquals(Integer.signum(cmp), Integer.signum(fast));
  }

  @Test
  void getPubKeyHash_returnsDefensiveCopy() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 1L);
    byte[] first = usk.getPubKeyHash();
    byte[] second = usk.getPubKeyHash();
    assertArrayEquals(bytes(NodeSSK.PUBKEY_HASH_SIZE, 0), first);
    assertArrayEquals(first, second);
    assertNotSame(first, second, "Should return a new array each time");

    // Mutate the returned array and ensure USK's behavior is unaffected
    first[0] ^= 0x7F;

    ClientSSK ssk = (ClientSSK) usk.getSSK();
    NodeSSK node = (NodeSSK) ssk.getNodeKey(false);
    assertTrue(usk.samePubKeyHash(node));
  }

  @Test
  void samePubKeyHash_detectsMismatch() throws MalformedURLException {
    USK usk = newUsk(SITE_NAME, 1L);
    byte[] otherHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 9);
    ClientSSK other =
        new ClientSSK(
            "site-1",
            otherHash,
            ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256),
            null,
            usk.getURI().getCryptoKey());
    NodeSSK node = (NodeSSK) other.getNodeKey(false);
    assertFalse(usk.samePubKeyHash(node));
  }
}

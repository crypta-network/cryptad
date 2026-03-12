package network.crypta.keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Random;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@SuppressWarnings("java:S100")
class FreenetURITest {
  // Some URI for wAnnA? index
  private static final String WANNA_USK_1 =
      "USK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search/17/index_d51.xml";
  private static final String WANNA_SSK_1 =
      "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17/index_d51.xml";
  private static final String WANNA_CHK_1 =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String KSK_EXAMPLE = "KSK@gpl.txt";

  @Test
  void sskForUSK_roundTripsBetweenUSKandSSK() throws MalformedURLException {
    FreenetURI uri1 = new FreenetURI(WANNA_USK_1);
    FreenetURI uri2 = new FreenetURI(WANNA_SSK_1);

    assertEquals(uri2, uri1.sskForUSK());
    assertEquals(uri1, uri2.uskForSSK());

    assertThrows(IllegalStateException.class, uri1::uskForSSK);
    assertThrows(IllegalStateException.class, uri2::sskForUSK);

    FreenetURI chkUriForThrows = new FreenetURI(WANNA_CHK_1);
    assertThrows(IllegalStateException.class, chkUriForThrows::sskForUSK);
    assertThrows(IllegalStateException.class, chkUriForThrows::uskForSSK);
    FreenetURI badSsk1 =
        new FreenetURI(
            "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17XXXX/index_d51.xml");
    assertThrows(IllegalStateException.class, badSsk1::sskForUSK);
    FreenetURI badSsk2 =
        new FreenetURI(
            "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search17/index_d51.xml");
    assertThrows(IllegalStateException.class, badSsk2::sskForUSK);
  }

  @Test
  void deriveRequestURIFromInsertURI_behavesPerType() throws MalformedURLException {
    final FreenetURI chk =
        new FreenetURI(
            "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    assertEquals(chk, chk.deriveRequestURIFromInsertURI());

    final FreenetURI ksk = new FreenetURI("KSK@test");
    assertEquals(ksk, ksk.deriveRequestURIFromInsertURI());

    final FreenetURI requestUriUSK =
        new FreenetURI(
            "USK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/WebOfTrust/5");
    final FreenetURI insertUriUSK =
        new FreenetURI(
            "USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/WebOfTrust/5");
    assertEquals(requestUriUSK, insertUriUSK.deriveRequestURIFromInsertURI());

    try {
      requestUriUSK.deriveRequestURIFromInsertURI();
      fail(
          "requestUriUSK.deriveRequestURIFromInsertURI() should fail because it IS a request URI"
              + " already!");
    } catch (MalformedURLException _) {
      // Success
    }

    final FreenetURI requestUriSSK =
        new FreenetURI(
            "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/WebOfTrust-5");
    final FreenetURI insertUriSSK =
        new FreenetURI(
            "SSK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/WebOfTrust-5");
    assertEquals(requestUriSSK, insertUriSSK.deriveRequestURIFromInsertURI());

    try {
      requestUriSSK.deriveRequestURIFromInsertURI();
      fail(
          "requestUriSSK.deriveRequestURIFromInsertURI() should fail because it IS a request URI"
              + " already!");
    } catch (MalformedURLException _) {
      // Success
    }

    final FreenetURI requestUriSSKPlain =
        new FreenetURI(
            "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/");
    final FreenetURI insertUriSSKPlain =
        new FreenetURI(
            "SSK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/");
    assertEquals(requestUriSSKPlain, insertUriSSKPlain.deriveRequestURIFromInsertURI());

    try {
      requestUriSSKPlain.deriveRequestURIFromInsertURI();
      fail(
          "requestUriSSKPlain.deriveRequestURIFromInsertURI() should fail because it IS a request"
              + " URI already!");
    } catch (MalformedURLException _) {
      // Success
    }
  }

  @Test
  void constructor_whenBrokenUSK_expectMalformedURLException() {
    try {
      new FreenetURI("USK@/broken/0");
      fail("USK@/broken/0 is not a valid USK.");
    } catch (MalformedURLException _) {
      // Works.
    }
  }

  @Test
  void constructor_whenBrokenSSK_expectMalformedURLException() {
    try {
      new FreenetURI("SSK@/broken-0");
      fail("SSK@/broken-0 is not a valid SSK.");
    } catch (MalformedURLException _) {
      // Works.
    }
  }

  @Test
  void constructor_allowsSSKWithoutRoutingKey() throws MalformedURLException {
    FreenetURI uri = new FreenetURI("SSK@");
    assertTrue(uri.isSSK());
    assertEquals("SSK@", uri.toString());
    assertNull(uri.getDocName());
    assertNull(uri.getRoutingKey());
    assertNull(uri.getCryptoKey());
  }

  @Test
  void constructor_acceptsKnownSchemesAndStripsPrefixes() throws MalformedURLException {
    for (String prefix :
        Arrays.asList(
            "freenet",
            "web+freenet",
            "ext+freenet",
            "hypha",
            "hyphanet",
            "web+hypha",
            "web+hyphanet",
            "ext+hypha",
            "ext+hyphanet")) {
      FreenetURI uri = new FreenetURI(prefix + ":" + WANNA_USK_1);
      assertEquals(WANNA_USK_1, uri.toString());
      uri = new FreenetURI(prefix + ":" + WANNA_SSK_1);
      assertEquals(WANNA_SSK_1, uri.toString());
      uri = new FreenetURI(prefix + ":" + WANNA_CHK_1);
      assertEquals(WANNA_CHK_1, uri.toString());
      uri = new FreenetURI(prefix + ":" + KSK_EXAMPLE);
      assertEquals(KSK_EXAMPLE, uri.toString());
    }
  }

  @Test
  void constructor_stripsHttpPrefixAndCustomSchemes() throws MalformedURLException {
    // Arrange + Act
    FreenetURI uri1 =
        new FreenetURI("https://host.example/freenet:" + "KSK@hello world/dir/%E2%9C%93");
    // Assert
    assertEquals("KSK@hello%20world/dir/✓", uri1.toString());

    FreenetURI uri2 = new FreenetURI("http://h/ext+hyphanet:" + KSK_EXAMPLE);
    assertEquals(KSK_EXAMPLE, uri2.toString());
  }

  @Test
  void toASCIIString_encodesNonAsciiWhileToStringAllowsUnicode() throws MalformedURLException {
    FreenetURI ksk = new FreenetURI("KSK@café/foß");
    // Non-ASCII remains in toString(); slashes are encoded
    assertEquals("KSK@café/foß", ksk.toString());
    // ASCII version percent-encodes non-ASCII and includes the freenet: prefix
    String expected =
        "freenet:KSK@"
            + network.crypta.support.URLEncoder.encode("café", "/", true)
            + "/"
            + network.crypta.support.URLEncoder.encode("foß", "/", true);
    assertEquals(expected, ksk.toASCIIString());
  }

  @Test
  void toRelativeURI_and_toURI_preserveEncoding() throws MalformedURLException, URISyntaxException {
    FreenetURI ksk = new FreenetURI("KSK@A/B C"); // slash will be encoded in the component
    URI rel = ksk.toRelativeURI();
    assertEquals("/" + ksk.toString(false, false), rel.toString());
    URI base = ksk.toURI("/base");
    assertEquals("/base" + ksk.toString(false, false), base.toString());
  }

  @Test
  void equals_hashCode_clone_and_equalsKeypair_contract() {
    Random r = new Random(42);
    FreenetURI chk1 = FreenetURI.generateRandomCHK(r);
    FreenetURI chk2 = new FreenetURI(chk1);

    assertNotNull(chk2);
    assertEquals(chk1, chk2);
    assertEquals(chk1.hashCode(), chk2.hashCode());
    assertTrue(chk1.equalsKeypair(chk2));

    FreenetURI withMeta = chk1.pushMetaString("file.txt");
    assertNotEquals(chk1, withMeta);
    assertTrue(chk1.equalsKeypair(withMeta)); // keypair unaffected by meta-strings
  }

  @Test
  void metaString_operations_add_push_pop_drop_behaveAndAreImmutable()
      throws MalformedURLException {
    FreenetURI uri = new FreenetURI(WANNA_SSK_1);

    FreenetURI appended = uri.addMetaStrings(new String[] {"a", "b"});
    assertArrayEquals(new String[] {"index_d51.xml", "a", "b"}, appended.getAllMetaStrings());

    FreenetURI appendedList = uri.addMetaStrings(Arrays.asList("x", "y"));
    assertArrayEquals(new String[] {"index_d51.xml", "x", "y"}, appendedList.getAllMetaStrings());

    FreenetURI pushed = uri.pushMetaString("z");
    assertArrayEquals(new String[] {"index_d51.xml", "z"}, pushed.getAllMetaStrings());

    FreenetURI popped = pushed.popMetaString();
    assertArrayEquals(new String[] {"index_d51.xml"}, popped.getAllMetaStrings());

    FreenetURI dropped = pushed.dropLastMetaStrings(2);
    assertNull(dropped.getAllMetaStrings());

    assertThrows(NullPointerException.class, () -> uri.pushMetaString(null));
  }

  @Test
  void setDocName_setSuggestedEdition_and_setRoutingKey_createNewInstances()
      throws MalformedURLException {
    FreenetURI usk = new FreenetURI(WANNA_USK_1);
    FreenetURI renamed = usk.setDocName("Site");
    assertEquals("Site", renamed.getDocName());
    assertNotEquals(usk, renamed);

    FreenetURI edited = usk.setSuggestedEdition(123);
    assertEquals(123, edited.getSuggestedEdition());
    assertNotEquals(usk, edited);

    byte[] rk = new byte[32];
    Arrays.fill(rk, (byte) 7);
    FreenetURI rerouted = usk.setRoutingKey(rk);
    assertArrayEquals(rk, rerouted.getRoutingKey());
  }

  @Test
  void getPreferredFilename_buildsMeaningfulNameAndFallsBack() throws MalformedURLException {
    // USK: docName + edition + metas
    FreenetURI usk =
        new FreenetURI(WANNA_USK_1).pushMetaString("dir").pushMetaString("file name.txt");
    String name = usk.getPreferredFilename();
    assertTrue(name.startsWith("Search-17-"));
    assertTrue(name.contains("-dir-file name.txt"));

    // SSK without docName or metaStrings -> fallback
    FreenetURI bare = new FreenetURI("SSK@");
    assertEquals("unknown", bare.getPreferredFilename());
  }

  @Test
  void binaryRoundTrip_CHK_and_KSK_and_USKFailure() throws Exception {
    // CHK round-trip
    FreenetURI chk = FreenetURI.generateRandomCHK(new Random(123));
    chk = chk.pushMetaString("index.html");
    byte[] written = writeWithLength(chk);
    FreenetURI parsed = readWithLength(written);
    assertEquals(chk, parsed);

    // KSK round-trip
    FreenetURI ksk = new FreenetURI("KSK", "doc.txt", new String[] {"a", "b"}, null, null, null);
    byte[] bin = writeWithLength(ksk);
    FreenetURI kskParsed = readWithLength(bin);
    assertEquals(ksk, kskParsed);

    // USK cannot be written as binary
    FreenetURI finalUsk =
        new FreenetURI(chk.getRoutingKey(), chk.getCryptoKey(), chk.getExtra(), "Site", 1);
    assertThrows(MalformedURLException.class, () -> writeWithLength(finalUsk));
  }

  @Test
  void isSSKForUSK_and_getEdition_behave() throws MalformedURLException {
    FreenetURI usk = new FreenetURI(WANNA_USK_1);
    FreenetURI ssk = usk.sskForUSK();
    assertTrue(ssk.isSSKForUSK());
    assertEquals(usk.getSuggestedEdition(), ssk.getEdition());

    FreenetURI notConvertible = new FreenetURI("SSK@");
    assertFalse(notConvertible.isSSKForUSK());
    assertThrows(IllegalStateException.class, notConvertible::getEdition);
  }

  @Test
  @SuppressWarnings("java:S1612")
  void checkInsertURI_throwsWhenMetaStringsPresent() {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(1)).pushMetaString("file");
    // Disambiguate overloaded methods by using explicit lambdas
    assertThrows(network.crypta.client.InsertException.class, uri::checkInsertURI);
    assertDoesNotThrow(FreenetURI.EMPTY_CHK_URI::checkInsertURI);
  }

  @Test
  void toShortString_containsEllipsisAndEncodedSegments() throws MalformedURLException {
    FreenetURI chk = new FreenetURI(WANNA_CHK_1);
    String shorty = chk.toShortString();
    assertTrue(shorty.startsWith("CHK@.../"));
    assertTrue(shorty.endsWith("/index_d51.xml"));
  }

  @Test
  void compareTo_and_FAST_COMPARATOR_consistentOrdering() throws MalformedURLException {
    FreenetURI a = new FreenetURI(WANNA_CHK_1);

    Comparator<FreenetURI> cmp = FreenetURI.FAST_COMPARATOR;
    // Sanity: equals -> compareTo 0 and comparator 0
    assertEquals(0, a.compareTo(new FreenetURI(WANNA_CHK_1)));
    assertEquals(0, cmp.compare(a, new FreenetURI(WANNA_CHK_1)));

    // Comparator is consistent with equals (0 when equals)
    assertEquals(0, cmp.compare(a, new FreenetURI(WANNA_CHK_1)));
  }

  @Test
  void constructor_CHK_allowsDotExtensionAfterTokens() throws MalformedURLException {
    // Arrange: a CHK with an artificial ".html" extension appended to the token string
    String chkWithExt =
        "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
            + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI.html";
    // Act
    FreenetURI chk = new FreenetURI(chkWithExt);
    // Assert: extension is ignored; there are no meta-strings, and toString omits the extension
    assertEquals(
        "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
            + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI",
        chk.toString());
    assertNull(chk.getAllMetaStrings());
  }

  // --- helpers ---
  private static byte[] writeWithLength(FreenetURI uri) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    uri.writeFullBinaryKeyWithLength(dos);
    dos.flush();
    return baos.toByteArray();
  }

  private static FreenetURI readWithLength(byte[] data) throws Exception {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
    return FreenetURI.readFullBinaryKeyWithLength(dis);
  }
}

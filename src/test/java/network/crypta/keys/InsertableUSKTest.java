package network.crypta.keys;

import java.net.MalformedURLException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.Global;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // test method naming uses given_when_then style
@ExtendWith(MockitoExtension.class)
class InsertableUSKTest {

  private static InsertableClientSSK newDeterministicInsertableSSK(String docName) {
    // Deterministic test key material: fixed-seed pseudo RNG
    DummyRandomSource rnd = new DummyRandomSource(0xC0FFEE); // fixed seed for determinism
    return InsertableClientSSK.createRandom(rnd, docName);
  }

  private static FreenetURI newInsertableUSKUri(InsertableClientSSK ssk, long edition) {
    // Build an SSK insert URI, then switch type to USK and set an edition.
    return ssk.getInsertURI().setKeyType("USK").setSuggestedEdition(edition);
  }

  @Test
  @DisplayName("createInsertable: non-USK URI -> MalformedURLException")
  void createInsertable_whenNotUSK_throwsMalformedURLException() {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("site");
    FreenetURI sskInsert = ssk.getInsertURI(); // Key type is SSK
    assertThrows(
        MalformedURLException.class, () -> InsertableUSK.createInsertable(sskInsert, true));
  }

  @Test
  @DisplayName("createInsertable: valid USK insert URI -> InsertableUSK with matching public USK")
  void createInsertable_withValidUSKInsertURI_returnsInsertableUSK() throws Exception {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("mysite");
    long edition = 12345L;
    FreenetURI uskInsert = newInsertableUSKUri(ssk, edition);

    InsertableUSK iusk = InsertableUSK.createInsertable(uskInsert, false);

    assertNotNull(iusk);
    assertNotNull(iusk.privKey);
    assertEquals("mysite", iusk.siteName);
    assertEquals(edition, iusk.suggestedEdition);
    // Public USK derived from the insertable must carry the same visible parameters
    USK pub = iusk.getUSK();
    assertEquals(iusk.siteName, pub.siteName);
    assertEquals(iusk.suggestedEdition, pub.suggestedEdition);
    assertEquals(iusk.cryptoAlgorithm, pub.cryptoAlgorithm);
    assertArrayEquals(iusk.getPubKeyHash(), pub.getPubKeyHash());

    // For any edition, the public SSK URI equals the fetch URI of the insertable SSK
    var insertableForEdition = iusk.getInsertableSSK(edition);
    var publicForEdition = pub.getSSK(edition);
    assertEquals(publicForEdition.getURI(), insertableForEdition.getURI());
  }

  @Test
  @DisplayName("getInsertableSSK(long): matches public SSK URI and material")
  void getInsertableSSK_whenUsingEdition_matchesPublicSSKURI() throws Exception {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("blog");
    long edition = 7L;
    InsertableUSK iusk = InsertableUSK.createInsertable(newInsertableUSKUri(ssk, edition), true);

    InsertableClientSSK issk = iusk.getInsertableSSK(edition);
    ClientSSK pubForEdition = iusk.getUSK().getSSK(edition);

    // URIs must match (insertable.getURI() is a fetch/public SSK URI)
    assertEquals(pubForEdition.getURI(), issk.getURI());

    // The pubKeyHash of the returned InsertableClientSSK must equal the hash of
    // the embedded public key
    DSAPublicKey embeddedPub = issk.getPubKey();
    assertNotNull(embeddedPub);
    assertArrayEquals(embeddedPub.asBytesHash(), issk.pubKeyHash);
  }

  @Test
  @DisplayName(
      "getInsertableSSK(String): null doc name throws Error with MalformedURLException cause")
  void getInsertableSSK_whenNullName_throwsError() throws Exception {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("docs");
    InsertableUSK iusk = InsertableUSK.createInsertable(newInsertableUSKUri(ssk, 1L), false);

    Error err = assertThrows(Error.class, () -> iusk.getInsertableSSK(null));
    assertNotNull(err.getCause());
    assertEquals(MalformedURLException.class, err.getCause().getClass());
  }

  @Test
  @DisplayName(
      "privCopy: same edition returns same instance; different edition returns updated copy")
  void privCopy_whenEditionChanged_behavesAsDocumented() throws Exception {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("media");
    long edition = 100L;
    InsertableUSK iusk = InsertableUSK.createInsertable(newInsertableUSKUri(ssk, edition), false);

    // Same edition -> identity
    assertSame(iusk, iusk.privCopy(edition));

    // Different edition -> new instance with identical keys and updated edition
    long newEdition = edition + 1;
    InsertableUSK copy = iusk.privCopy(newEdition);
    assertNotSame(iusk, copy);
    assertEquals(newEdition, copy.suggestedEdition);
    assertEquals(iusk.siteName, copy.siteName);
    assertEquals(iusk.cryptoAlgorithm, copy.cryptoAlgorithm);
    assertSame(iusk.privKey, copy.privKey);
    assertArrayEquals(iusk.getPubKeyHash(), copy.getPubKeyHash());
  }

  @Test
  @DisplayName("getCryptoGroup: returns BigA")
  void getCryptoGroup_returnsBigA() throws Exception {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("group");
    InsertableUSK iusk = InsertableUSK.createInsertable(newInsertableUSKUri(ssk, 2L), false);
    assertSame(Global.DSAgroupBigA, iusk.getCryptoGroup());
  }

  @Test
  @DisplayName("createInsertable: USK with public extras (not insert) -> MalformedURLException")
  void createInsertable_withPublicExtras_throwsMalformedURLException() {
    InsertableClientSSK ssk = newDeterministicInsertableSSK("site");
    long edition = 42L;
    // Build a USK URI that carries the private key in the routing field but marks extras as public
    byte[] publicExtras = ClientSSK.getExtraBytes(ssk.cryptoAlgorithm); // extra[1] == 0
    // Reuse the routing bytes from the SSK insert URI to avoid direct private key access.
    byte[] privateKeyBytes = ssk.getInsertURI().getRoutingKey();
    FreenetURI bad =
        new FreenetURI(
            "USK",
            ssk.docName,
            null, // no metastrings
            privateKeyBytes, // routing field carries the private DSA x
            ssk.cryptoKey,
            publicExtras,
            edition);

    assertThrows(MalformedURLException.class, () -> InsertableUSK.createInsertable(bad, true));
  }
}

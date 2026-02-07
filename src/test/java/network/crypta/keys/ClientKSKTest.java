package network.crypta.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import network.crypta.crypt.SHA256;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientKSKTest {

  @Test
  void create_whenKeywordProvided_expectDeterministicAndCorrectFields()
      throws MalformedURLException {
    // Arrange
    String keyword = "hello.txt";

    // Act
    ClientKSK a = ClientKSK.create(keyword);
    ClientKSK b = ClientKSK.create(keyword);

    // Assert (basic invariants)
    assertNotNull(a);
    assertNotNull(b);
    assertEquals(keyword, a.docName);
    assertEquals(keyword, b.docName);
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, a.cryptoAlgorithm);
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, b.cryptoAlgorithm);

    // Determinism: same keyword yields identical keys and URIs
    assertEquals(a, b);
    assertEquals(a.getURI(), b.getURI());

    // Crypto key should be SHA-256(keyword UTF-8)
    MessageDigest md = SHA256.getMessageDigest();
    byte[] expectedKeywordHash = md.digest(keyword.getBytes(StandardCharsets.UTF_8));
    assertArrayEquals(expectedKeywordHash, a.cryptoKey);

    // PubKey hash should be SHA-256(pubKey.asBytes())
    byte[] expectedPubKeyHash = md.digest(a.pubKey.asBytes());
    assertArrayEquals(expectedPubKeyHash, a.pubKeyHash);

    // getURI should be a KSK with matching docName and round-trip parse
    FreenetURI uri = a.getURI();
    assertEquals("KSK", uri.getKeyType());
    assertEquals(keyword, uri.getDocName());
    // Round-trip without prefix
    assertEquals(uri, new FreenetURI(uri.toString()));
  }

  @Test
  void create_whenDifferentKeywords_expectDifferentKeys() {
    // Arrange
    String k1 = "foo";
    String k2 = "bar";

    // Act
    ClientKSK a = ClientKSK.create(k1);
    ClientKSK b = ClientKSK.create(k2);

    // Assert
    assertNotEquals(a, b);
    assertNotEquals(a.getURI(), b.getURI());
    assertNotEquals(a.docName, b.docName);
    // Distinct crypto keys and public key hashes (byte-wise)
    assertNotNull(a.cryptoKey);
    assertNotNull(b.cryptoKey);
    assertFalse(java.util.Arrays.equals(a.cryptoKey, b.cryptoKey));
    assertNotNull(a.pubKeyHash);
    assertNotNull(b.pubKeyHash);
    assertFalse(java.util.Arrays.equals(a.pubKeyHash, b.pubKeyHash));
  }

  @Test
  void create_whenEmptyKeyword_expectValidKSK() {
    // Arrange
    String keyword = "";

    // Act
    ClientKSK ksk = ClientKSK.create(keyword);

    // Assert
    assertNotNull(ksk);
    assertEquals("", ksk.docName);
    FreenetURI uri = ksk.getURI();
    assertEquals("KSK", uri.getKeyType());
    assertEquals("", uri.getDocName());
    // Determinism for empty keyword
    assertEquals(ksk, ClientKSK.create(""));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void create_whenNullKeyword_expectNullPointerException() {
    // Arrange / Act / Assert
    assertThrows(NullPointerException.class, () -> ClientKSK.create((String) null));
  }

  @Test
  void create_withKskURIWithMeta_expectMatchesCreateWithDocName() throws MalformedURLException {
    // Arrange: KSK with docname and additional meta strings (which are ignored for creating KSK)
    String raw = "dir/read me.txt";
    FreenetURI uriWithMeta = new FreenetURI("KSK@" + raw + "/meta1/meta2");

    // Act
    InsertableClientSSK fromUri = ClientKSK.fromUri(uriWithMeta);
    // For KSK, the docName is the first path segment after '@'
    String expectedDocName = uriWithMeta.getDocName();
    assertNotNull(expectedDocName);
    ClientKSK fromDocName = ClientKSK.create(expectedDocName);

    // Assert: identical key material
    assertEquals(fromDocName, fromUri);
    assertEquals(fromDocName.getURI(), fromUri.getURI());
  }

  @Test
  void create_withNonKskURI_expectIllegalArgumentException() {
    // Arrange: construct a minimal valid CHK URI without randomness
    byte[] rkey = new byte[32];
    byte[] ckey = new byte[32];
    FreenetURI chk = new FreenetURI("CHK", null, rkey, ckey, null);

    // Act / Assert
    assertThrows(IllegalArgumentException.class, () -> ClientKSK.fromUri(chk));
  }
}

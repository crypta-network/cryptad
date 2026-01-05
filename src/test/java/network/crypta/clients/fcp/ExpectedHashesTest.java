package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

@SuppressWarnings("java:S100")
class ExpectedHashesTest {

  @Test
  void getFieldSet_whenEventHasHashes_expectFieldSetContainsHashes() throws Exception {
    HashResult sha1 = createHash(HashType.SHA1, (byte) 0x01);
    HashResult sha256 = createHash(HashType.SHA256, (byte) 0x02);
    ExpectedHashesEvent event = new ExpectedHashesEvent(new HashResult[] {sha1, sha256});

    ExpectedHashes expectedHashes = new ExpectedHashes(event, "identifier-123", true);

    SimpleFieldSet fieldSet = expectedHashes.getFieldSet();

    assertNotNull(fieldSet);
    SimpleFieldSet hashesSubset = fieldSet.subset("Hashes");
    assertNotNull(hashesSubset);
    assertEquals("identifier-123", fieldSet.getString("Identifier"));
    assertEquals("true", fieldSet.get("Global"));
    assertEquals(sha1.hashAsHex(), hashesSubset.getString(HashType.SHA1.name()));
    assertEquals(sha256.hashAsHex(), hashesSubset.getString(HashType.SHA256.name()));
  }

  @Test
  void getFieldSet_whenIdentifierNull_expectIdentifierMissing() throws Exception {
    HashResult sha1 = createHash(HashType.SHA1, (byte) 0x05);
    ExpectedHashes expectedHashes = new ExpectedHashes(new HashResult[] {sha1}, null, false);

    SimpleFieldSet fieldSet = expectedHashes.getFieldSet();

    assertNotNull(fieldSet);
    assertNull(fieldSet.get("Identifier"));
    assertEquals("false", fieldSet.get("Global"));
    SimpleFieldSet hashesSubset = fieldSet.subset("Hashes");
    assertNotNull(hashesSubset);
    assertEquals(sha1.hashAsHex(), hashesSubset.getString(HashType.SHA1.name()));
  }

  @Test
  void getFieldSet_whenDuplicateTypes_expectLastValueWins() throws Exception {
    HashResult first = createHash(HashType.SHA1, (byte) 0x10);
    HashResult second = createHash(HashType.SHA1, (byte) 0x20);
    ExpectedHashes expectedHashes =
        new ExpectedHashes(new HashResult[] {first, second}, "dup-test", true);

    SimpleFieldSet fieldSet = expectedHashes.getFieldSet();

    assertNotNull(fieldSet);
    SimpleFieldSet hashesSubset = fieldSet.subset("Hashes");
    assertNotNull(hashesSubset);
    assertEquals(second.hashAsHex(), hashesSubset.getString(HashType.SHA1.name()));
  }

  @Test
  void getFieldSet_whenHashesNull_expectNullFieldSet() {
    ExpectedHashes expectedHashes = new ExpectedHashes((HashResult[]) null, "n/a", false);

    assertNull(expectedHashes.getFieldSet());
  }

  @Test
  void getFieldSet_whenHashEntryNull_expectNullFieldSet() {
    HashResult sha1 = createHash(HashType.SHA1, (byte) 0x03);
    ExpectedHashes expectedHashes = new ExpectedHashes(new HashResult[] {sha1, null}, "id", true);

    assertNull(expectedHashes.getFieldSet());
  }

  @Test
  void getName_whenCalled_expectExpectedHashes() {
    ExpectedHashes expectedHashes = new ExpectedHashes(new HashResult[0], "id", false);

    assertEquals("ExpectedHashes", expectedHashes.getName());
  }

  @Test
  void run_whenInvoked_expectUnsupportedOperationException() {
    ExpectedHashes expectedHashes = new ExpectedHashes(new HashResult[0], "run", false);

    assertThrows(
        UnsupportedOperationException.class,
        () ->
            expectedHashes.run(
                Mockito.mock(FCPConnectionHandler.class),
                Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));
  }

  private static HashResult createHash(HashType type, byte fillValue) {
    byte[] data = new byte[type.hashLength];
    Arrays.fill(data, fillValue);
    return new HashResult(type, data);
  }
}

package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubscribedUSKUpdateTest {

  @Test
  void getName_whenCalled_returnsSubscribedUSKUpdate() throws Exception {
    SubscribedUSKUpdate update =
        new SubscribedUSKUpdate("test-id", 42L, createUsk(42L), true, false);

    assertEquals("SubscribedUSKUpdate", update.getName());
  }

  @Test
  void getFieldSet_whenCreated_populatesAllFields() throws Exception {
    String identifier = "ident-123";
    long edition = 123L;
    boolean newKnownGood = true;
    boolean newSlotToo = false;
    USK usk = createUsk(edition);
    SubscribedUSKUpdate update =
        new SubscribedUSKUpdate(identifier, edition, usk, newKnownGood, newSlotToo);

    SimpleFieldSet fieldSet = update.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals(identifier, fieldSet.get("Identifier"));
    assertEquals(Long.toString(edition), fieldSet.get("Edition"));
    assertEquals(usk.getURI().toString(), fieldSet.get("URI"));
    assertEquals(Boolean.toString(newKnownGood), fieldSet.get("NewKnownGood"));
    assertEquals(Boolean.toString(newSlotToo), fieldSet.get("NewSlotToo"));
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithDetails() throws Exception {
    String identifier = "run-test";
    long edition = 7L;
    USK usk = createUsk(edition);
    SubscribedUSKUpdate update = new SubscribedUSKUpdate(identifier, edition, usk, false, true);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () ->
                update.run(
                    mock(FCPConnectionHandler.class),
                    mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
    assertEquals(
        "SubscribedUSKUpdate goes from server to client not the other way around",
        exception.getMessage());
  }

  private static USK createUsk(long edition) throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    for (int i = 0; i < pubKeyHash.length; i++) {
      pubKeyHash[i] = (byte) i;
    }
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    for (int i = 0; i < cryptoKey.length; i++) {
      cryptoKey[i] = (byte) (i + 1);
    }
    byte[] extras =
        new byte[] {
          (byte) NodeSSK.SSK_VERSION,
          0,
          Key.ALGO_AES_PCFB_256_SHA256,
          0,
          (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extras, "test-site", edition);
  }
}

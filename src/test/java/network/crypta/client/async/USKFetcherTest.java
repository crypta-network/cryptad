package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.RequestStarter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKFetcherTest {

  private USK usk;
  @Mock private USKManager uskManager;
  @Mock private ClientRequester requester;
  @Mock private ClientContext clientContext;

  private FetchContext fetchContext;

  // Deterministic key material for tests
  private DSAPublicKey pubKey;
  private byte[] pubKeyHash;
  private byte cryptoAlgorithm;

  @BeforeEach
  void setUp() throws Exception {
    // Deterministic public key (small, valid y)
    pubKey = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(2));
    pubKeyHash = SHA256.digest(pubKey.asBytes());
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    new Random(42).nextBytes(cryptoKey);
    cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;

    // Build extras for SSK/USK (version, fetch URI marker, algorithm, HASH_SHA256)
    byte[] extras =
        new byte[] {NodeSSK.SSK_VERSION, 0, cryptoAlgorithm, 0, (byte) KeyBlock.HASH_SHA256};

    // Construct a USK with deterministic material
    usk = new USK(pubKeyHash, cryptoKey, extras, "testsite", 0L);

    // Minimal real FetchContext (used/cloned by USKFetcher)
    fetchContext =
        new FetchContext(
            64 * 1024,
            64 * 1024,
            1024,
            1,
            0,
            0,
            true,
            0,
            0,
            3,
            true,
            false,
            false,
            false,
            0,
            0,
            new SimpleEventProducer(),
            true,
            false,
            null,
            null,
            null);

    // Common requester stubs
    when(requester.realTimeFlag()).thenReturn(false);
  }

  private USKFetcher newFetcher() {
    // minFailures=3; no background poll; keepLastData=false; checkStoreOnly=false
    return new USKFetcher(usk, uskManager, fetchContext, requester, 3, 0);
  }

  // Positive handleBlock path omitted: requires a fully-formed SSKBlock instance including valid
  // structural header fields and crypto binding. We cover the negative branch and validate matcher
  // logic via definitelyWantKey/probablyWantKey for deterministic behavior.

  @Test
  @DisplayName("handleBlock_whenNonSSKBlock_returnsFalse")
  void handleBlock_whenNonSSKBlock_returnsFalse() {
    USKFetcher fetcher = newFetcher();
    KeyBlock nonSSK = mock(KeyBlock.class);
    NodeSSK anyKey = mock(NodeSSK.class);

    boolean handled = fetcher.handleBlock(anyKey, new byte[] {0x00}, nonSSK, clientContext);
    assertFalse(handled, "Non-SSK blocks must be ignored");
  }

  @Test
  @DisplayName("definitelyWantKey_whenMatching_returnsProgressPriority")
  void definitelyWantKey_whenMatching_returnsProgressPriority() throws Exception {
    USKFetcher fetcher = newFetcher();
    ClientSSK cskEd1 = usk.getSSK(1L);
    NodeSSK nodeKey = new NodeSSK(pubKeyHash, cskEd1.ehDocname, pubKey, cryptoAlgorithm);

    when(uskManager.lookupLatestSlot(usk)).thenReturn(0L);
    short prio = fetcher.definitelyWantKey(nodeKey, new byte[] {0x01}, clientContext);
    assertEquals(
        fetcher.getPriorityClass(),
        prio,
        "Matching key should be wanted at the fetcher's progress priority");
  }

  @Test
  @DisplayName("probablyWantKey_whenWrongPubKeyHash_returnsFalse")
  void probablyWantKey_whenWrongPubKeyHash_returnsFalse() throws Exception {
    USKFetcher fetcher = newFetcher();
    // Create a NodeSSK with a different public key hash
    DSAPublicKey otherPk = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(3));
    byte[] otherHash = SHA256.digest(otherPk.asBytes());
    ClientSSK cskEd1 = usk.getSSK(1L);
    NodeSSK wrong = new NodeSSK(otherHash, cskEd1.ehDocname, otherPk, cryptoAlgorithm);

    assertFalse(
        fetcher.probablyWantKey(wrong, new byte[] {0x02}),
        "Mismatched pubkey hash must be rejected");
  }

  @Test
  @DisplayName("getters_basicBehaviors")
  void getters_basicBehaviors() {
    USKFetcher fetcher = newFetcher();
    assertEquals(usk.getURI(), fetcher.getURI(), "getURI should proxy the original USK URI");
    assertEquals(usk, fetcher.getOriginalUSK(), "getOriginalUSK should return the same instance");
    assertFalse(fetcher.isFinished(), "Fresh fetcher should not be finished");
    assertTrue(fetcher.isSSK(), "USK fetchers operate on SSKs");
    assertFalse(fetcher.persistent(), "USKFetcher is not persistent");
    assertEquals(RequestStarter.UPDATE_PRIORITY_CLASS, fetcher.getPriorityClass());
    assertArrayEquals(
        usk.getPubKeyHash(), fetcher.getWantedKey(), "Wanted key should match USK pubkey hash");
  }

  @Test
  @DisplayName("subscriber_add_and_remove")
  void subscriber_add_and_remove() {
    USKFetcher fetcher = newFetcher();

    // Minimal USKCallback implementation
    USKCallback cb =
        new USKCallback() {
          @Override
          public short getPollingPriorityNormal() {
            return RequestStarter.PREFETCH_PRIORITY_CLASS;
          }

          @Override
          public short getPollingPriorityProgress() {
            return RequestStarter.UPDATE_PRIORITY_CLASS;
          }

          @Override
          public void onFoundEdition(
              long ed,
              USK key,
              ClientContext context,
              boolean metadata,
              short codec,
              byte[] data,
              boolean newKnownGood,
              boolean newSlotToo) {
            // Intentionally empty for this test: the callback exists only to
            // exercise subscriber add/remove mechanics. No behavior under test
            // depends on receiving or handling edition notifications here.
          }
        };

    fetcher.addSubscriber(cb, 5L);
    assertTrue(fetcher.hasSubscribers(), "Fetcher should track the added subscriber");

    when(uskManager.lookupLatestSlot(usk)).thenReturn(0L);
    fetcher.removeSubscriber(cb);
    assertFalse(fetcher.hasSubscribers(), "Subscriber removal should be reflected");
  }

  @Test
  @DisplayName("getRequestsForKey_returnsEmptyArray")
  void getRequestsForKey_returnsEmptyArray() throws Exception {
    USKFetcher fetcher = newFetcher();
    ClientSSK cskEd1 = usk.getSSK(1L);
    NodeSSK nodeKey = new NodeSSK(pubKeyHash, cskEd1.ehDocname, pubKey, cryptoAlgorithm);
    assertEquals(0, fetcher.getRequestsForKey(nodeKey, new byte[] {0}, clientContext).length);
  }
}

package network.crypta.store;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.util.List;
import network.crypta.crypt.DSAPublicKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** Smoke tests verifying that PR2 SLF4J refactors emit logs at expected levels/messages. */
public class StoreLoggingTest {

  private Logger ramLogger;
  private Logger simpleGetPubkeyLogger;
  private ListAppender<ILoggingEvent> ramListAppender;
  private ListAppender<ILoggingEvent> simpleListAppender;
  private Level ramOriginalLevel;
  private Level simpleOriginalLevel;

  @BeforeEach
  public void setup() {
    ramLogger = (Logger) LoggerFactory.getLogger(RAMFreenetStore.class);
    simpleGetPubkeyLogger = (Logger) LoggerFactory.getLogger(SimpleGetPubkey.class);

    ramOriginalLevel = ramLogger.getLevel();
    simpleOriginalLevel = simpleGetPubkeyLogger.getLevel();

    // Attach in-memory appenders
    ramListAppender = new ListAppender<>();
    ramListAppender.start();
    ramLogger.addAppender(ramListAppender);
    // Be permissive for this test; RAM store logs at INFO for the scenario under test
    ramLogger.setLevel(Level.INFO);

    simpleListAppender = new ListAppender<>();
    simpleListAppender.start();
    simpleGetPubkeyLogger.addAppender(simpleListAppender);
    simpleGetPubkeyLogger.setLevel(Level.ERROR);
  }

  @AfterEach
  public void tearDown() {
    if (ramLogger != null && ramListAppender != null) {
      ramLogger.detachAppender(ramListAppender);
      ramLogger.setLevel(ramOriginalLevel);
    }
    if (simpleGetPubkeyLogger != null && simpleListAppender != null) {
      simpleGetPubkeyLogger.detachAppender(simpleListAppender);
      simpleGetPubkeyLogger.setLevel(simpleOriginalLevel);
    }
  }

  @Test
  public void ramStore_logsIgnoringOldBlock_info() throws Exception {
    // Minimal callback and block to exercise the INFO path
    TestCallback cb = new TestCallback();
    RAMFreenetStore<TestBlock> store = new RAMFreenetStore<>(cb, 10);

    byte[] rk = new byte[] {1, 2};
    byte[] fk = new byte[] {3, 4};
    TestBlock block = new TestBlock(rk, fk);

    // Insert as an old block
    store.put(block, new byte[] {9}, new byte[] {8}, false, true);

    // Fetch with ignoreOldBlocks=true to trigger the info log and early return
    TestBlock result =
        store.fetch(rk, fk, /*dontPromote*/ true, false, false, /*ignoreOldBlocks*/ true, null);

    // Not found due to ignoreOldBlocks
    assertThat(result, is((TestBlock) null));

    List<ILoggingEvent> events = ramListAppender.list;
    assertThat(events, notNullValue());
    boolean sawMessage =
        events.stream()
            .anyMatch(
                e ->
                    e.getLevel() == Level.INFO
                        && e.getFormattedMessage().contains("Ignoring old block"));
    assertThat("Expected INFO log 'Ignoring old block'", sawMessage, is(true));
  }

  @Test
  public void simpleGetPubkey_logsError_onIOException() {
    // Stub PubkeyStore that throws IOException in both fetch() and put()
    PubkeyStore throwingStore =
        new PubkeyStore() {
          @Override
          public DSAPublicKey fetch(
              byte[] hash, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta)
              throws IOException {
            throw new IOException("boom-fetch");
          }

          @Override
          public void put(byte[] hash, DSAPublicKey key, boolean isOldBlock) throws IOException {
            throw new IOException("boom-put");
          }
        };

    SimpleGetPubkey gp = new SimpleGetPubkey(throwingStore);
    byte[] hash = new byte[] {0x0A};

    // Triggers error log in getKey()
    gp.getKey(hash, false, false, null);
    // Triggers error log in cacheKey(); key may be null since the override throws before use
    gp.cacheKey(hash, null, false, false, false, false, false);

    List<ILoggingEvent> events = simpleListAppender.list;
    boolean hasError = events.stream().anyMatch(e -> e.getLevel() == Level.ERROR);
    assertThat("Expected at least one ERROR log from SimpleGetPubkey", hasError, is(true));
  }

  // --- Test helpers ---

  private static final class TestBlock implements StorableBlock {
    private final byte[] rk;
    private final byte[] fk;

    TestBlock(byte[] rk, byte[] fk) {
      this.rk = rk;
      this.fk = fk;
    }

    @Override
    public byte[] getRoutingKey() {
      return rk;
    }

    @Override
    public byte[] getFullKey() {
      return fk;
    }
  }

  private static final class TestCallback extends StoreCallback<TestBlock> {
    @Override
    public int dataLength() {
      return 1;
    }

    @Override
    public int headerLength() {
      return 1;
    }

    @Override
    public int routingKeyLength() {
      return 2;
    }

    @Override
    public boolean storeFullKeys() {
      return true;
    }

    @Override
    public boolean constructNeedsKey() {
      return false;
    }

    @Override
    public int fullKeyLength() {
      return 2;
    }

    @Override
    public boolean collisionPossible() {
      return false;
    }

    @Override
    public TestBlock construct(
        byte[] data,
        byte[] headers,
        byte[] routingKey,
        byte[] fullKey,
        boolean canReadClientCache,
        boolean canReadSlashdotCache,
        BlockMetadata meta,
        DSAPublicKey ignored) {
      return new TestBlock(routingKey, fullKey);
    }

    @Override
    public byte[] routingKeyFromFullKey(byte[] keyBuf) {
      return keyBuf;
    }
  }
}

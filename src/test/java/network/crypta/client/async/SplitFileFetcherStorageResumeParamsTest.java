package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.client.FetchContext;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.RandomSource;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherStorageResumeParamsTest {
  @Mock private LockableRandomAccessBuffer raf;
  @Mock private SplitFileFetcherStorageCallback callback;
  @Mock private FetchContext origContext;
  @Mock private RandomSource random;
  @Mock private PersistentJobRunner exec;
  @Mock private KeysFetchingLocally keysFetching;
  @Mock private Ticker ticker;
  @Mock private MemoryLimitedJobRunner memoryLimitedJobRunner;
  @Mock private ChecksumChecker checker;
  @Mock private KeySalter salt;

  @Test
  void build_whenNoValuesProvided_expectDefaultsNullAndFalse() {
    SplitFileFetcherStorageResumeParams.Builder builder =
        new SplitFileFetcherStorageResumeParams.Builder();

    SplitFileFetcherStorageResumeParams params = builder.build();

    assertAll(
        "defaults",
        () -> assertNull(params.raf),
        () -> assertFalse(params.realTime),
        () -> assertNull(params.callback),
        () -> assertNull(params.origContext),
        () -> assertNull(params.random),
        () -> assertNull(params.exec),
        () -> assertNull(params.keysFetching),
        () -> assertNull(params.ticker),
        () -> assertNull(params.memoryLimitedJobRunner),
        () -> assertNull(params.checker),
        () -> assertFalse(params.newSalt),
        () -> assertNull(params.salt),
        () -> assertFalse(params.resumed),
        () -> assertFalse(params.completeViaTruncation));
  }

  @Test
  void build_whenAllValuesProvided_expectSameReferencesAndFlags() {
    SplitFileFetcherStorageResumeParams.Builder builder =
        new SplitFileFetcherStorageResumeParams.Builder()
            .raf(raf)
            .realTime(true)
            .callback(callback)
            .context(origContext)
            .random(random)
            .exec(exec)
            .keysFetching(keysFetching)
            .ticker(ticker)
            .memoryLimitedJobRunner(memoryLimitedJobRunner)
            .checker(checker)
            .newSalt(true)
            .salt(salt)
            .resumed(true)
            .completeViaTruncation(true);

    SplitFileFetcherStorageResumeParams params = builder.build();

    assertAll(
        "values",
        () -> assertSame(raf, params.raf),
        () -> assertTrue(params.realTime),
        () -> assertSame(callback, params.callback),
        () -> assertSame(origContext, params.origContext),
        () -> assertSame(random, params.random),
        () -> assertSame(exec, params.exec),
        () -> assertSame(keysFetching, params.keysFetching),
        () -> assertSame(ticker, params.ticker),
        () -> assertSame(memoryLimitedJobRunner, params.memoryLimitedJobRunner),
        () -> assertSame(checker, params.checker),
        () -> assertTrue(params.newSalt),
        () -> assertSame(salt, params.salt),
        () -> assertTrue(params.resumed),
        () -> assertTrue(params.completeViaTruncation));
  }

  @Test
  void builderMethods_whenInvoked_expectSameBuilderInstance() {
    SplitFileFetcherStorageResumeParams.Builder builder =
        new SplitFileFetcherStorageResumeParams.Builder();

    assertAll(
        "fluent",
        () -> assertSame(builder, builder.raf(raf)),
        () -> assertSame(builder, builder.realTime(true)),
        () -> assertSame(builder, builder.callback(callback)),
        () -> assertSame(builder, builder.context(origContext)),
        () -> assertSame(builder, builder.random(random)),
        () -> assertSame(builder, builder.exec(exec)),
        () -> assertSame(builder, builder.keysFetching(keysFetching)),
        () -> assertSame(builder, builder.ticker(ticker)),
        () -> assertSame(builder, builder.memoryLimitedJobRunner(memoryLimitedJobRunner)),
        () -> assertSame(builder, builder.checker(checker)),
        () -> assertSame(builder, builder.newSalt(true)),
        () -> assertSame(builder, builder.salt(salt)),
        () -> assertSame(builder, builder.resumed(true)),
        () -> assertSame(builder, builder.completeViaTruncation(true)));
  }
}

package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.Metadata;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherStorageInitParamsTest {

  @Mock private Metadata metadata;
  @Mock private SplitFileFetcherStorageCallback fetcher;
  @Mock private ClientMetadata clientMetadata;
  @Mock private FetchContext fetchContext;
  @Mock private KeySalter keySalter;
  @Mock private RandomSource random;
  @Mock private BucketFactory tempBucketFactory;
  @Mock private LockableRandomAccessBufferFactory rafFactory;
  @Mock private PersistentJobRunner exec;
  @Mock private Ticker ticker;
  @Mock private MemoryLimitedJobRunner memoryLimitedJobRunner;
  @Mock private ChecksumChecker checker;
  @Mock private FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory;
  @Mock private KeysFetchingLocally keysFetching;

  @Test
  void build_whenNoValuesProvided_expectDefaults() {
    // Arrange
    SplitFileFetcherStorageInitParams.Builder builder =
        new SplitFileFetcherStorageInitParams.Builder();

    // Act
    SplitFileFetcherStorageInitParams params = builder.build();

    // Assert
    assertNull(params.metadata);
    assertNull(params.fetcher);
    assertNull(params.decompressors);
    assertNull(params.clientMetadata);
    assertFalse(params.topDontCompress);
    assertEquals((short) 0, params.topCompatibilityMode);
    assertNull(params.origFetchContext);
    assertNull(params.salt);
    assertNull(params.thisKey);
    assertNull(params.origKey);
    assertFalse(params.isFinalFetch);
    assertNull(params.clientDetails);
    assertNull(params.random);
    assertNull(params.tempBucketFactory);
    assertNull(params.rafFactory);
    assertNull(params.exec);
    assertNull(params.ticker);
    assertNull(params.memoryLimitedJobRunner);
    assertNull(params.checker);
    assertFalse(params.persistent);
    assertNull(params.storageFile);
    assertNull(params.diskSpaceCheckingRAFFactory);
    assertNull(params.keysFetching);
  }

  @Test
  void build_whenAllValuesProvided_expectFieldsAssigned() {
    // Arrange
    List<COMPRESSOR_TYPE> decompressors = List.of(COMPRESSOR_TYPE.GZIP, COMPRESSOR_TYPE.BZIP2);
    FreenetURI thisKey = new FreenetURI("CHK", "doc");
    FreenetURI origKey = new FreenetURI("KSK", "orig");
    byte[] clientDetails = new byte[] {1, 2, 3, 4};
    File storageFile = new File("storage.dat");

    SplitFileFetcherStorageInitParams.Builder builder =
        new SplitFileFetcherStorageInitParams.Builder()
            .metadata(metadata)
            .fetcher(fetcher)
            .decompressors(decompressors)
            .clientMetadata(clientMetadata)
            .topDontCompress(true)
            .topCompatibilityMode((short) 7)
            .fetchContext(fetchContext)
            .salt(keySalter)
            .thisKey(thisKey)
            .origKey(origKey)
            .isFinalFetch(true)
            .clientDetails(clientDetails)
            .random(random)
            .tempBucketFactory(tempBucketFactory)
            .rafFactory(rafFactory)
            .exec(exec)
            .ticker(ticker)
            .memoryLimitedJobRunner(memoryLimitedJobRunner)
            .checker(checker)
            .persistent(true)
            .storageFile(storageFile)
            .diskSpaceCheckingRAFFactory(diskSpaceCheckingRAFFactory)
            .keysFetching(keysFetching);

    // Act
    SplitFileFetcherStorageInitParams params = builder.build();

    // Assert
    assertSame(metadata, params.metadata);
    assertSame(fetcher, params.fetcher);
    assertEquals(decompressors, params.decompressors);
    assertSame(clientMetadata, params.clientMetadata);
    assertTrue(params.topDontCompress);
    assertEquals((short) 7, params.topCompatibilityMode);
    assertSame(fetchContext, params.origFetchContext);
    assertSame(keySalter, params.salt);
    assertSame(thisKey, params.thisKey);
    assertSame(origKey, params.origKey);
    assertTrue(params.isFinalFetch);
    assertArrayEquals(clientDetails, params.clientDetails);
    assertSame(random, params.random);
    assertSame(tempBucketFactory, params.tempBucketFactory);
    assertSame(rafFactory, params.rafFactory);
    assertSame(exec, params.exec);
    assertSame(ticker, params.ticker);
    assertSame(memoryLimitedJobRunner, params.memoryLimitedJobRunner);
    assertSame(checker, params.checker);
    assertTrue(params.persistent);
    assertSame(storageFile, params.storageFile);
    assertSame(diskSpaceCheckingRAFFactory, params.diskSpaceCheckingRAFFactory);
    assertSame(keysFetching, params.keysFetching);
  }

  @Test
  void build_whenBuilderReused_expectIndependentSnapshots() {
    // Arrange
    Metadata firstMetadata = metadata;
    Metadata secondMetadata = org.mockito.Mockito.mock(Metadata.class);
    SplitFileFetcherStorageInitParams.Builder builder =
        new SplitFileFetcherStorageInitParams.Builder().metadata(firstMetadata);

    // Act
    SplitFileFetcherStorageInitParams firstParams = builder.build();
    builder.metadata(secondMetadata);
    SplitFileFetcherStorageInitParams secondParams = builder.build();

    // Assert
    assertSame(firstMetadata, firstParams.metadata);
    assertSame(secondMetadata, secondParams.metadata);
    assertNotSame(firstParams, secondParams);
  }

  @ParameterizedTest
  @CsvSource({"true,true", "false,false", "true,false", "false,true"})
  void build_whenBooleanFlagsProvided_expectValuesPropagated(
      boolean topDontCompress, boolean persistent) {
    // Arrange
    SplitFileFetcherStorageInitParams.Builder builder =
        new SplitFileFetcherStorageInitParams.Builder()
            .topDontCompress(topDontCompress)
            .persistent(persistent);

    // Act
    SplitFileFetcherStorageInitParams params = builder.build();

    // Assert
    assertEquals(topDontCompress, params.topDontCompress);
    assertEquals(persistent, params.persistent);
  }
}

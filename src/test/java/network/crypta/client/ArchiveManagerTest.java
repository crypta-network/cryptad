package network.crypta.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ArchiveManagerTest {

  @Mock private ClientContext clientContext;

  @Mock private ArchiveExtractCallback callback;

  private BucketFactory bf;

  @BeforeEach
  void setup() {
    bf = new ArrayBucketFactory();
  }

  @Test
  void archiveType_staticHelpers_coverValidInvalidMappings() {
    // Arrange & Act & Assert
    assertEquals(ARCHIVE_TYPE.TAR, ARCHIVE_TYPE.getDefault());

    // metadata IDs
    assertTrue(ARCHIVE_TYPE.isValidMetadataID((short) 0));
    assertTrue(ARCHIVE_TYPE.isValidMetadataID((short) 1));
    assertFalse(ARCHIVE_TYPE.isValidMetadataID((short) 999));

    // string mime lookups (case-insensitive)
    assertEquals(ARCHIVE_TYPE.ZIP, ARCHIVE_TYPE.getArchiveType("application/zip"));
    assertEquals(ARCHIVE_TYPE.ZIP, ARCHIVE_TYPE.getArchiveType("APPLICATION/X-ZIP"));
    assertEquals(ARCHIVE_TYPE.TAR, ARCHIVE_TYPE.getArchiveType("application/x-tar"));
    assertNull(ARCHIVE_TYPE.getArchiveType("application/x-7z"));

    // usability
    assertTrue(ARCHIVE_TYPE.isUsableArchiveType("application/zip"));
    assertFalse(ARCHIVE_TYPE.isUsableArchiveType("application/x-7z"));

    // short code lookups
    assertEquals(ARCHIVE_TYPE.ZIP, ARCHIVE_TYPE.getArchiveType((short) 0));
    assertEquals(ARCHIVE_TYPE.TAR, ARCHIVE_TYPE.getArchiveType((short) 1));
    assertNull(ARCHIVE_TYPE.getArchiveType((short) 5));
  }

  @Test
  void makeContext_and_cache_evictionByHandlerLimit() {
    // Arrange
    ArchiveManager mgr =
        new ArchiveManager(1, /*maxCachedData*/ 1 << 20, /*maxArchivedFileSize*/ 1 << 20, 16, bf);
    FreenetURI k1 = new FreenetURI("KSK", "a");
    FreenetURI k2 = new FreenetURI("KSK", "b");

    // No context yet, and we ask to return null if not found
    ArchiveStoreContext none = mgr.makeContext(k1, ARCHIVE_TYPE.TAR, null, true);
    assertNull(none);

    // Create first context
    ArchiveStoreContext c1 = mgr.makeContext(k1, ARCHIVE_TYPE.TAR, null, false);
    assertNotNull(c1);
    // Reuse from cache
    ArchiveStoreContext c1Again = mgr.makeContext(k1, ARCHIVE_TYPE.TAR, null, false);
    assertEquals(c1, c1Again);

    // Create another context; with maxHandlers=1 it should evict the first
    ArchiveStoreContext c2 = mgr.makeContext(k2, ARCHIVE_TYPE.TAR, null, false);
    assertNotNull(c2);

    // Validate eviction by consulting package-private getCached(FreenetURI)
    assertNull(mgr.getCached(k1));
    assertEquals(c2, mgr.getCached(k2));
  }

  @Test
  void makeHandler_and_clone_preserveConfiguration() {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "doc");

    // Act
    ArchiveHandler h = mgr.makeHandler(key, ARCHIVE_TYPE.ZIP, COMPRESSOR_TYPE.GZIP, false, false);
    ArchiveHandler clone = h.cloneHandler();

    // Assert
    assertEquals(key, h.getKey());
    assertEquals(ARCHIVE_TYPE.ZIP, h.getArchiveType());
    assertEquals(key, clone.getKey());
    assertEquals(h.getArchiveType(), clone.getArchiveType());
  }

  @Test
  void getCached_whenNothingStored_returnsNull() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "empty");

    // Act & Assert
    assertNull(mgr.getCached(key, "missing.txt"));
  }

  @Test
  void extractToCache_zip_withElement_present_callsCallbackAndCachesEntry() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-present");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.txt", "hello world".getBytes(StandardCharsets.UTF_8));
    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx), elementRequest("a.txt"));

      // Assert: callback got the requested entry
      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());

      byte[] got = BucketTools.toByteArray(bucketCaptor.getValue());
      assertArrayEquals(entries.get("a.txt"), got);

      // And cache can serve it too
      Bucket cached = mgr.getCached(key, "a.txt");
      assertNotNull(cached);
      try {
        assertArrayEquals(entries.get("a.txt"), BucketTools.toByteArray(cached));
      } finally {
        cached.free();
      }

      // Metadata is generated when missing
      Bucket meta = mgr.getCached(key, ".metadata");
      assertNotNull(meta);
      meta.free();
    }
  }

  @Test
  void extractToCache_zip_withMissingElement_callsNotInArchive() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-missing");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.txt", "hello".getBytes(StandardCharsets.UTF_8));
    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest("missing.txt"));

      // Assert: callback says it's missing
      verify(callback, times(1)).notInArchive(clientContext);
      verify(callback, never())
          .onFailed(org.mockito.Mockito.any(ArchiveFailureException.class), any());
    }
  }

  @Test
  void extractToCache_zip_entryTooBig_notRequested_storesErrorAndCacheReturnsNull()
      throws Exception {
    // Arrange (limit smaller than entry)
    long maxFile = 5L;
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, maxFile, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-big");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    byte[] payload = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("big.bin", payload);
    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act (request a non-existent element to avoid null gotElement)
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest("__unused__"));

      // Assert: too big entry is represented as an error item; cache lookup yields null bucket
      assertNull(mgr.getCached(key, "big.bin"));
    }
  }

  @Test
  void extractToCache_zip_entryTooBig_requested_resultsInNotInArchive_andCacheNull()
      throws Exception {
    // Arrange (limit smaller than entry)
    long maxFile = 5L;
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, maxFile, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-big-requested");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    byte[] payload = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("big.bin", payload);
    try (Bucket data = new SimpleReadOnlyArrayBucket(createStoredZip(entries))) {
      // Act: request the big element explicitly
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx), elementRequest("big.bin"));

      // Assert: current implementation reports not-in-archive for too-big entries (no callback
      // data)
      verify(callback, times(1)).notInArchive(clientContext);
      // Cached representation is an error item → null bucket from getCached
      assertNull(mgr.getCached(key, "big.bin"));
    }
  }

  @Test
  void extractToCache_zip_whenArchiveHasTooManyEntries_throwsArchiveFailureException()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 16 << 20, 1 << 20, 16_384, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-too-many-entries");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(16 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    for (int i = 0; i <= 10_000; i++) {
      entries.put("entry-" + i + ".txt", new byte[] {'x'});
    }

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      ArchiveFailureException thrown =
          assertThrows(
              ArchiveFailureException.class,
              () ->
                  mgr.extractToCache(
                      extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
                      elementRequest("__unused__")));

      // Assert
      assertTrue(thrown.getMessage().contains("too many entries"), thrown.getMessage());
    }
  }

  @Test
  void extractToCache_tarGzip_whenExpandedArchiveExceedsContextLimit_throwsArchiveFailureException()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 4 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-gzip-expanded-too-big");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.bin", new byte[384 << 10]);
    entries.put("b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      // Act
      ArchiveFailureException thrown =
          assertThrows(
              ArchiveFailureException.class,
              () ->
                  mgr.extractToCache(
                      extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
                      elementRequest("__unused__")));

      // Assert
      assertTrue(
          thrown.getMessage().contains("Expanded archive exceeds configured limit"),
          thrown.getMessage());
    }
  }

  @Test
  void
      extractToCache_zip_whenSkippedOversizedEntriesExpandPastContextLimit_throwsArchiveFailureException()
          throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-skipped-expanded-too-big");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.bin", new byte[384 << 10]);
    entries.put("b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      ArchiveFailureException thrown =
          assertThrows(
              ArchiveFailureException.class,
              () ->
                  mgr.extractToCache(
                      extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
                      elementRequest("__unused__")));

      // Assert
      assertTrue(
          thrown.getMessage().contains("Expanded archive exceeds configured limit"),
          thrown.getMessage());
    }
  }

  @Test
  void
      extractToCache_tarGzip_whenSkippedOversizedEntriesExpandPastContextLimit_throwsArchiveFailureException()
          throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-gzip-skipped-expanded-too-big");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.bin", new byte[384 << 10]);
    entries.put("b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      // Act
      ArchiveFailureException thrown =
          assertThrows(
              ArchiveFailureException.class,
              () ->
                  mgr.extractToCache(
                      extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
                      elementRequest("__unused__")));

      // Assert
      assertTrue(
          thrown.getMessage().contains("Expanded archive exceeds configured limit"),
          thrown.getMessage());
    }
  }

  @Test
  void extractToCache_zip_whenRequestedEntryFoundBeforeLaterOversizedEntries_returnsSuccess()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-requested-before-skipped-tail");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    byte[] wanted = "wanted".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.txt", wanted);
    entries.put("big-a.bin", new byte[384 << 10]);
    entries.put("big-b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest("wanted.txt"));

      // Assert
      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_tarGzip_whenRequestedEntryFoundBeforeLaterOversizedEntries_returnsSuccess()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-requested-before-skipped-tail");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    byte[] wanted = "wanted".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.txt", wanted);
    entries.put("big-a.bin", new byte[384 << 10]);
    entries.put("big-b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
          elementRequest("wanted.txt"));

      // Assert
      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_zip_whenRequestedEntryExceedsArchiveContextLimit_returnsSuccess()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 512 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-requested-exceeds-archive-context-limit");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(256 << 10, 8);

    byte[] wanted = new byte[384 << 10];
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.bin", wanted);

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest("wanted.bin"));

      // Assert
      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_tarGzip_whenRequestedEntryExceedsArchiveContextLimit_returnsSuccess()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 512 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-requested-exceeds-archive-context-limit");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(256 << 10, 8);

    byte[] wanted = new byte[384 << 10];
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.bin", wanted);

    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
          elementRequest("wanted.bin"));

      // Assert
      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_zip_whenCallbackThrows_cacheEntryRemainsReadable() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-callback-throws-cache-retained");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    byte[] wanted = "cache me".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.txt", wanted);

    RuntimeException thrownByCallback = new RuntimeException("boom");
    org.mockito.Mockito.doThrow(thrownByCallback)
        .when(callback)
        .gotBucket(any(Bucket.class), org.mockito.Mockito.eq(clientContext));

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      ArchiveExtractionInput input = extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx);
      ArchiveElementRequest request = elementRequest("wanted.txt");

      // Act + Assert
      RuntimeException thrown =
          assertThrows(RuntimeException.class, () -> mgr.extractToCache(input, request));
      assertEquals(thrownByCallback, thrown);

      Bucket cached = mgr.getCached(key, "wanted.txt");
      assertNotNull(cached);
      try {
        assertArrayEquals(wanted, BucketTools.toByteArray(cached));
      } finally {
        cached.free();
      }
    }
  }

  @Test
  void extractToCache_zip_whenArchiveChangedAndTailHitsScanLimit_throwsRestartAfterCallback()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-restart-after-tail-limit");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    byte[] wanted = "wanted".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.txt", wanted);
    entries.put("big-a.bin", new byte[384 << 10]);
    entries.put("big-b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      ctx.setLastSize(1L);
      ctx.setLastHash(new byte[] {1, 2, 3});

      // Act + Assert
      assertThrows(
          ArchiveRestartException.class,
          () ->
              mgr.extractToCache(
                  extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
                  elementRequest("wanted.txt")));

      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_tarGzip_whenArchiveChangedAndTailHitsScanLimit_throwsRestartAfterCallback()
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 256 << 10, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-restart-after-tail-limit");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(512 << 10, 8);

    byte[] wanted = "wanted".getBytes(StandardCharsets.UTF_8);
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("wanted.txt", wanted);
    entries.put("big-a.bin", new byte[384 << 10]);
    entries.put("big-b.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      ctx.setLastSize(1L);
      ctx.setLastHash(new byte[] {1, 2, 3});

      // Act + Assert
      assertThrows(
          ArchiveRestartException.class,
          () ->
              mgr.extractToCache(
                  extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
                  elementRequest("wanted.txt")));

      ArgumentCaptor<Bucket> bucketCaptor = ArgumentCaptor.forClass(Bucket.class);
      verify(callback, times(1))
          .gotBucket(bucketCaptor.capture(), org.mockito.Mockito.eq(clientContext));
      verify(callback, never()).notInArchive(any());
      assertArrayEquals(wanted, BucketTools.toByteArray(bucketCaptor.getValue()));
    }
  }

  @Test
  void extractToCache_zip_whenExpandedLimitTripsMidEntry_freesTempBucket() throws Exception {
    // Arrange
    TrackingBucketFactory trackingFactory = new TrackingBucketFactory();
    ArchiveManager mgr = new ArchiveManager(2, 4 << 20, 4 << 20, 16, trackingFactory);
    FreenetURI key = new FreenetURI("KSK", "zip-mid-entry-limit-frees-bucket");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(256 << 10, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("big.bin", new byte[384 << 10]);

    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      assertThrows(
          ArchiveFailureException.class,
          () ->
              mgr.extractToCache(
                  extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
                  elementRequest("__unused__")));

      // Assert
      assertEquals(1, trackingFactory.freedBuckets());
    }
  }

  @Test
  void extractToCache_tar_gzip_outerCompression_supported_andNamesStripped() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "tar-gz");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    // The handler should strip leading slash
    entries.put("/dir/a.txt", "xyz".getBytes(StandardCharsets.UTF_8));
    try (Bucket data = new SimpleReadOnlyArrayBucket(gzip(createTar(entries)))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.TAR, COMPRESSOR_TYPE.GZIP, data, actx, ctx),
          elementRequest("dir/a.txt"));

      // Assert: the element is cached and callback invoked
      Bucket cached = mgr.getCached(key, "dir/a.txt");
      assertNotNull(cached);
      try {
        assertArrayEquals("xyz".getBytes(StandardCharsets.UTF_8), BucketTools.toByteArray(cached));
      } finally {
        cached.free();
      }
      verify(callback, times(1))
          .gotBucket(any(Bucket.class), org.mockito.Mockito.eq(clientContext));
    }
  }

  @Test
  void extractToCache_whenSizeOrHashChanged_throwsRestart_butCachesEntries() throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-restart");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put("a.txt", "payload".getBytes(StandardCharsets.UTF_8));
    byte[] zip = createZip(entries);
    try (Bucket data = new SimpleReadOnlyArrayBucket(zip)) {
      // Force restart via lastSize mismatch and lastHash mismatch
      ctx.setLastSize(1L); // definitely not equal to zip.length
      ctx.setLastHash(new byte[] {1, 2, 3});

      // Act + Assert: extraction throws restart
      assertThrows(
          ArchiveRestartException.class,
          () ->
              mgr.extractToCache(
                  extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
                  elementRequest("__unused__")));

      // But entries should be cached regardless
      Bucket cached = mgr.getCached(key, "a.txt");
      assertNotNull(cached);
      try {
        assertArrayEquals(entries.get("a.txt"), BucketTools.toByteArray(cached));
      } finally {
        cached.free();
      }
    }
  }

  @Test
  void trimStoredData_whenElementLimitExceeded_evictsLeastRecent() throws Exception {
    // Arrange: keep only 1 cached element
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 1, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-evict");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put(".metadata", "M".getBytes(StandardCharsets.UTF_8));
    entries.put("a.txt", "A".getBytes(StandardCharsets.UTF_8));
    entries.put("b.txt", "B".getBytes(StandardCharsets.UTF_8));
    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act: extract; the manager will add entries in iteration order (.metadata, a then b)
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest("__unused__"));

      // Assert: only the most recent (b.txt) remains due to maxCachedElements=1
      assertNull(mgr.getCached(key, ".metadata"));
      assertNull(mgr.getCached(key, "a.txt"));
      Bucket bCached = mgr.getCached(key, "b.txt");
      assertNotNull(bCached);
      bCached.free();
    }
  }

  @ParameterizedTest
  @CsvSource({"/file.txt,file.txt", "//nested/path.txt,nested/path.txt"})
  void extractToCache_zip_stripsLeadingSlashes(String entryName, String expectedStoredName)
      throws Exception {
    // Arrange
    ArchiveManager mgr = new ArchiveManager(2, 1 << 20, 1 << 20, 16, bf);
    FreenetURI key = new FreenetURI("KSK", "zip-strips");
    ArchiveStoreContext ctx = mgr.makeContext(key, ARCHIVE_TYPE.ZIP, null, false);
    ArchiveContext actx = new ArchiveContext(1 << 20, 8);

    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put(entryName, "Z".getBytes(StandardCharsets.UTF_8));
    try (Bucket data = new SimpleReadOnlyArrayBucket(createZip(entries))) {
      // Act
      mgr.extractToCache(
          extractionInput(key, ARCHIVE_TYPE.ZIP, null, data, actx, ctx),
          elementRequest(expectedStoredName));

      // Assert
      Bucket cached = mgr.getCached(key, expectedStoredName);
      assertNotNull(cached);
      try {
        assertArrayEquals("Z".getBytes(StandardCharsets.UTF_8), BucketTools.toByteArray(cached));
      } finally {
        cached.free();
      }
    }
  }

  // ----------------- Helpers -----------------

  private ArchiveExtractionInput extractionInput(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressorType,
      Bucket data,
      ArchiveContext archiveContext,
      ArchiveStoreContext storeContext) {
    return new ArchiveExtractionInput(
        key, archiveType, compressorType, data, archiveContext, storeContext);
  }

  private ArchiveElementRequest elementRequest(String element) {
    return new ArchiveElementRequest(element, callback, clientContext);
  }

  private static byte[] createZip(Map<String, byte[]> entries) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      for (Map.Entry<String, byte[]> e : entries.entrySet()) {
        ZipEntry ze = new ZipEntry(e.getKey());
        // Make test data deterministic
        ze.setTime(0L);
        zos.putNextEntry(ze);
        zos.write(e.getValue());
        zos.closeEntry();
      }
    }
    return baos.toByteArray();
  }

  private static byte[] createStoredZip(Map<String, byte[]> entries) throws IOException {
    java.util.zip.CRC32 crc = new java.util.zip.CRC32();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      for (Map.Entry<String, byte[]> e : entries.entrySet()) {
        byte[] data = e.getValue();
        crc.reset();
        crc.update(data);
        ZipEntry ze = new ZipEntry(e.getKey());
        ze.setTime(0L);
        ze.setMethod(ZipEntry.STORED);
        ze.setSize(data.length);
        ze.setCompressedSize(data.length);
        ze.setCrc(crc.getValue());
        zos.putNextEntry(ze);
        zos.write(data);
        zos.closeEntry();
      }
    }
    return baos.toByteArray();
  }

  private static byte[] createTar(Map<String, byte[]> entries) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (TarArchiveOutputStream tos = new TarArchiveOutputStream(baos)) {
      tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
      for (Map.Entry<String, byte[]> e : entries.entrySet()) {
        String name = e.getKey();
        byte[] data = e.getValue();
        TarArchiveEntry te = new TarArchiveEntry(name);
        te.setModTime(0);
        te.setSize(data.length);
        tos.putArchiveEntry(te);
        tos.write(data);
        tos.closeArchiveEntry();
      }
    }
    return baos.toByteArray();
  }

  private static byte[] gzip(byte[] in) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
      gos.write(in);
    }
    return baos.toByteArray();
  }

  private static final class TrackingBucketFactory implements BucketFactory {
    private final AtomicInteger freedBuckets = new AtomicInteger();

    @Override
    public RandomAccessBucket makeBucket(long size) {
      return new TrackingArrayBucket(freedBuckets);
    }

    private int freedBuckets() {
      return freedBuckets.get();
    }
  }

  private static final class TrackingArrayBucket extends ArrayBucket {
    private final AtomicInteger freedBuckets;
    private boolean freed;

    private TrackingArrayBucket(AtomicInteger freedBuckets) {
      this.freedBuckets = freedBuckets;
    }

    @Override
    public void free() {
      if (!freed) {
        freed = true;
        freedBuckets.incrementAndGet();
      }
      super.free();
    }
  }
}

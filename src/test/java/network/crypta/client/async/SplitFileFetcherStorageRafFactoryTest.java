package network.crypta.client.async;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.PooledFileRandomAccessBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherStorageRafFactoryTest {
  private static final String STORAGE_FILE_NAME = "storage.dat";
  private static final String EXPECTED_IO_EXCEPTION_MESSAGE = "Expected IOException";

  @TempDir Path tempDir;

  @Test
  void createRafOrThrow_whenStorageFileNull_usesInMemoryFactory() throws Exception {
    long totalLength = 128L;
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    CapturingRafFactory rafFactory = new CapturingRafFactory(raf);
    CapturingFileRafFactory diskFactory =
        new CapturingFileRafFactory(mock(PooledFileRandomAccessBuffer.class));
    RandomSource random = mock(RandomSource.class);
    Logger log = mock(Logger.class);

    try (LockableRandomAccessBuffer result =
        SplitFileFetcherStorageRafFactory.createRafOrThrow(
            null, totalLength, rafFactory, diskFactory, random, log)) {
      assertSame(raf, result);
    }
    assertEquals(1, rafFactory.callCount);
    assertEquals(totalLength, rafFactory.lastSize);
    assertEquals(0, diskFactory.callCount);
  }

  @Test
  void createRafOrThrow_whenStorageFileProvidedWithoutDiskFactory_throwsIOException() {
    long totalLength = 64L;
    File storageFile = tempDir.resolve(STORAGE_FILE_NAME).toFile();
    LockableRandomAccessBufferFactory rafFactory = mock(LockableRandomAccessBufferFactory.class);
    RandomSource random = mock(RandomSource.class);
    Logger log = mock(Logger.class);

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> {
              try (LockableRandomAccessBuffer raf =
                  SplitFileFetcherStorageRafFactory.createRafOrThrow(
                      storageFile, totalLength, rafFactory, null, random, log)) {
                fail(EXPECTED_IO_EXCEPTION_MESSAGE + ": " + raf);
              }
            });

    assertEquals(
        "Disk-space checking RAF factory required for file-backed storage", thrown.getMessage());
  }

  @Test
  void createRafOrThrow_whenStorageFileMissing_throwsIOException() {
    long totalLength = 64L;
    File storageFile = tempDir.resolve("missing.dat").toFile();
    CapturingRafFactory rafFactory =
        new CapturingRafFactory(mock(LockableRandomAccessBuffer.class));
    CapturingFileRafFactory diskFactory =
        new CapturingFileRafFactory(mock(PooledFileRandomAccessBuffer.class));
    RandomSource random = mock(RandomSource.class);
    Logger log = mock(Logger.class);

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> {
              try (LockableRandomAccessBuffer raf =
                  SplitFileFetcherStorageRafFactory.createRafOrThrow(
                      storageFile, totalLength, rafFactory, diskFactory, random, log)) {
                fail(EXPECTED_IO_EXCEPTION_MESSAGE + ": " + raf);
              }
            });

    assertEquals("Must have already created storage file", thrown.getMessage());
    assertEquals(0, diskFactory.callCount);
  }

  @Test
  void createRafOrThrow_whenStorageFileNotEmpty_throwsIOException() throws Exception {
    long totalLength = 64L;
    Path storagePath = tempDir.resolve(STORAGE_FILE_NAME);
    Files.write(storagePath, new byte[] {1});
    File storageFile = storagePath.toFile();
    CapturingRafFactory rafFactory =
        new CapturingRafFactory(mock(LockableRandomAccessBuffer.class));
    CapturingFileRafFactory diskFactory =
        new CapturingFileRafFactory(mock(PooledFileRandomAccessBuffer.class));
    RandomSource random = mock(RandomSource.class);
    Logger log = mock(Logger.class);

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> {
              try (LockableRandomAccessBuffer raf =
                  SplitFileFetcherStorageRafFactory.createRafOrThrow(
                      storageFile, totalLength, rafFactory, diskFactory, random, log)) {
                fail(EXPECTED_IO_EXCEPTION_MESSAGE + ": " + raf);
              }
            });

    assertEquals("Storage file must be empty", thrown.getMessage());
    assertEquals(0, diskFactory.callCount);
  }

  @Test
  void createRafOrThrow_whenStorageFileEmpty_usesDiskFactory() throws Exception {
    long totalLength = 512L;
    Path storagePath = tempDir.resolve(STORAGE_FILE_NAME);
    Files.createFile(storagePath);
    File storageFile = storagePath.toFile();
    CapturingRafFactory rafFactory =
        new CapturingRafFactory(mock(LockableRandomAccessBuffer.class));
    RandomSource random = mock(RandomSource.class);
    Logger log = mock(Logger.class);
    PooledFileRandomAccessBuffer raf = mock(PooledFileRandomAccessBuffer.class);
    CapturingFileRafFactory diskFactory = new CapturingFileRafFactory(raf);

    try (LockableRandomAccessBuffer result =
        SplitFileFetcherStorageRafFactory.createRafOrThrow(
            storageFile, totalLength, rafFactory, diskFactory, random, log)) {
      assertSame(raf, result);
    }
    assertEquals(0, rafFactory.callCount);
    assertEquals(1, diskFactory.callCount);
    assertSame(storageFile, diskFactory.lastFile);
    assertEquals(totalLength, diskFactory.lastSize);
    assertSame(random, diskFactory.lastRandom);
    verify(log)
        .info("Creating splitfile storage file for complete-via-truncation: {}", storageFile);
  }

  private static final class CapturingRafFactory implements LockableRandomAccessBufferFactory {
    private final LockableRandomAccessBuffer raf;
    private int callCount;
    private long lastSize = -1;

    private CapturingRafFactory(LockableRandomAccessBuffer raf) {
      this.raf = raf;
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(long size) {
      callCount++;
      lastSize = size;
      return raf;
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(
        byte[] initialContents, int offset, int size, boolean readOnly) {
      throw new UnsupportedOperationException("Not needed for tests");
    }
  }

  private static final class CapturingFileRafFactory implements FileRandomAccessBufferFactory {
    private final PooledFileRandomAccessBuffer raf;
    private int callCount;
    private File lastFile;
    private long lastSize;
    private Random lastRandom;

    private CapturingFileRafFactory(PooledFileRandomAccessBuffer raf) {
      this.raf = raf;
    }

    @Override
    public PooledFileRandomAccessBuffer createNewRAF(File file, long size, Random random) {
      callCount++;
      lastFile = file;
      lastSize = size;
      lastRandom = random;
      return raf;
    }
  }
}

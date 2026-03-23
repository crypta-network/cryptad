package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Locale;
import java.util.Random;
import java.util.stream.Stream;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.DelayedFree;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Unit tests for {@link EncryptedRandomAccessBuffer}.
 *
 * <p>Strategy: - Use in-memory or file-backed underlying RAFs with deterministic {@link
 * MasterSecret}. - Verify header handling (new vs. existing), bounds, close semantics, resume
 * behavior, and persistence round-trips via {@link BucketTools#restoreRAFFrom}.
 */
@SuppressWarnings("java:S100")
class EncryptedRandomAccessBufferTest {

  @BeforeAll
  static void ensureJceLoaded() {
    // Ensure providers/algorithms are registered (BC etc.).
    JceLoader.dumpLoaded();
  }

  private static MasterSecret deterministicSecret() {
    byte[] s = new byte[64];
    for (int i = 0; i < s.length; i++) s[i] = (byte) (i ^ 0xA5);
    return new MasterSecret(s);
  }

  static Stream<EncryptedRandomAccessBufferType> types() {
    return Stream.of(EncryptedRandomAccessBufferType.values());
  }

  // ---------------- Construction & size ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("size_whenNewFile_expectUnderlyingMinusHeaderLen")
  void size_whenNewFile_expectUnderlyingMinusHeaderLen(EncryptedRandomAccessBufferType type)
      throws Exception {
    // Arrange
    int payload = 256;
    long underlyingSize = (long) type.headerLen + payload;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer((int) underlyingSize);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      assertEquals(payload, raf.size());
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("constructor_whenUnderlyingTooSmall_expectIOException")
  void constructor_whenUnderlyingTooSmall_expectIOException(EncryptedRandomAccessBufferType type) {
    // Arrange: underlying smaller than header
    try (LockableRandomAccessBuffer tiny =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen - 1)) {
      assertThrows(
          IOException.class,
          () -> new EncryptedRandomAccessBuffer(type, tiny, deterministicSecret(), true));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("constructor_whenExistingAndBadMagic_expectIOException")
  void constructor_whenExistingAndBadMagic_expectIOException(EncryptedRandomAccessBufferType type) {
    // Arrange: the header area is zeroed -> bad magic
    try (LockableRandomAccessBuffer underlying =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + 10)) {
      assertThrows(
          IOException.class,
          () -> new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), false));
    }
  }

  // ---------------- Read/Write ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pwrite_pread_whenRoundTrip_expectOriginalBytes")
  void pwrite_pread_whenRoundTrip_expectOriginalBytes(EncryptedRandomAccessBufferType type)
      throws Exception {
    // Arrange
    int payload = 512;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      byte[] data = new byte[payload];
      for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
      raf.pwrite(0, data, 0, data.length);
      byte[] out = new byte[payload];
      raf.pread(0, out, 0, out.length);
      assertArrayEquals(data, out);

      byte[] chunk = new byte[100];
      for (int i = 0; i < chunk.length; i++) chunk[i] = (byte) (255 - i);
      int off = 50;
      raf.pwrite(off, chunk, 0, chunk.length);
      byte[] chk = new byte[chunk.length];
      raf.pread(off, chk, 0, chk.length);
      assertArrayEquals(chunk, chk);
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pread_whenNegativeOffset_expectIllegalArgumentException")
  void pread_whenNegativeOffset_expectIllegalArgumentException(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 32;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      assertThrows(IllegalArgumentException.class, () -> raf.pread(-1, new byte[1], 0, 1));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pwrite_whenNegativeOffset_expectIllegalArgumentException")
  void pwrite_whenNegativeOffset_expectIllegalArgumentException(
      EncryptedRandomAccessBufferType type) throws Exception {
    int payload = 32;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      assertThrows(IllegalArgumentException.class, () -> raf.pwrite(-1, new byte[1], 0, 1));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pread_whenBeyondEnd_expectIOException")
  void pread_whenBeyondEnd_expectIOException(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 16;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      assertThrows(IOException.class, () -> raf.pread(0, new byte[17], 0, 17));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pwrite_whenBeyondEnd_expectIOException")
  void pwrite_whenBeyondEnd_expectIOException(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 16;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      assertThrows(IOException.class, () -> raf.pwrite(8, new byte[12], 0, 12));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("pread_pwrite_afterClose_expectIOException")
  void pread_pwrite_afterClose_expectIOException(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 8;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      raf.close();
      assertThrows(IOException.class, () -> raf.pread(0, new byte[1], 0, 1));
      assertThrows(IOException.class, () -> raf.pwrite(0, new byte[1], 0, 1));
    }
  }

  // ---------------- Header verify (existing) ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("constructor_whenExistingWithSameSecret_canReadPlaintext")
  void constructor_whenExistingWithSameSecret_canReadPlaintext(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 128;
    try (LockableRandomAccessBuffer underlying =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload)) {
      MasterSecret secret = deterministicSecret();
      byte[] data = new byte[payload];
      for (int i = 0; i < payload; i++) data[i] = (byte) (i * 3);

      EncryptedRandomAccessBuffer first =
          new EncryptedRandomAccessBuffer(type, underlying, secret, true);
      first.pwrite(0, data, 0, data.length);

      // Act: reopen over the same underlying with newFile=false
      try (EncryptedRandomAccessBuffer reopened =
          new EncryptedRandomAccessBuffer(type, underlying, secret, false)) {
        byte[] out = new byte[payload];
        reopened.pread(0, out, 0, out.length);
        assertArrayEquals(data, out);
      }
      // Now safe to close the original wrapper
      first.close();
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("constructor_whenExistingWithWrongSecret_expectGeneralSecurityException")
  void constructor_whenExistingWithWrongSecret_expectGeneralSecurityException(
      EncryptedRandomAccessBufferType type) throws Exception {
    int payload = 64;
    try (LockableRandomAccessBuffer underlying =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload)) {
      MasterSecret correct = deterministicSecret();
      MasterSecret wrong = new MasterSecret(new byte[64]);

      EncryptedRandomAccessBuffer first =
          new EncryptedRandomAccessBuffer(type, underlying, correct, true);
      first.pwrite(0, new byte[payload], 0, payload);

      assertThrows(
          java.security.GeneralSecurityException.class,
          () -> new EncryptedRandomAccessBuffer(type, underlying, wrong, false));
      first.close();
    }
  }

  // ---------------- lockOpen ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("lockOpen_whenUnlockTwice_secondUnlockThrows")
  void lockOpen_whenUnlockTwice_secondUnlockThrows(EncryptedRandomAccessBufferType type)
      throws Exception {
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + 1);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      LockableRandomAccessBuffer.RAFLock lock = raf.lockOpen();
      lock.unlock();
      assertThrows(IllegalStateException.class, lock::unlock);
    }
  }

  // ---------------- onResume ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("onResume_whenSameSecret_expectReadable")
  void onResume_whenSameSecret_expectReadable(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 32;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      MasterSecret secret = deterministicSecret();
      byte[] data = new byte[payload];
      for (int i = 0; i < data.length; i++) data[i] = (byte) (i + 7);
      raf.pwrite(0, data, 0, data.length);

      CryptoResumeContext ctx = Mockito.mock(CryptoResumeContext.class);
      Mockito.when(ctx.getPersistentMasterSecret()).thenReturn(secret);

      // Act
      raf.onResume(ctx);

      // Assert: still readable and data intact
      byte[] out = new byte[payload];
      raf.pread(0, out, 0, out.length);
      assertArrayEquals(data, out);
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("onResume_whenWrongSecret_expectResumeFailedException")
  void onResume_whenWrongSecret_expectResumeFailedException(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 8;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      raf.pwrite(0, new byte[payload], 0, payload);

      CryptoResumeContext ctx = Mockito.mock(CryptoResumeContext.class);
      Mockito.when(ctx.getPersistentMasterSecret()).thenReturn(new MasterSecret(new byte[64]));

      assertThrows(ResumeFailedException.class, () -> raf.onResume(ctx));
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("onResume_whenResumeContextIsNotCrypto_expectResumeFailedException")
  void onResume_whenResumeContextIsNotCrypto_expectResumeFailedException(
      EncryptedRandomAccessBufferType type) throws Exception {
    int payload = 8;
    try (LockableRandomAccessBuffer underlying =
            new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, underlying, deterministicSecret(), true)) {
      raf.pwrite(0, new byte[payload], 0, payload);
      ResumeContext context = Mockito.mock(ResumeContext.class);

      ResumeFailedException exception =
          assertThrows(ResumeFailedException.class, () -> raf.onResume(context));

      assertEquals(
          "Encrypted persistent state requires a CryptoResumeContext", exception.getMessage());
    }
  }

  // ---------------- storeTo / restoreRAFFrom round-trip ----------------

  @TempDir File tmpDir;

  private record DummyTracker(File dir, FilenameGenerator gen) implements PersistentFileTracker {

    @Override
    public void register(File file) {
      // no-op for tests
    }

    @Override
    public long commitID() {
      return 1L;
    }

    @Override
    public void delayedFree(DelayedFree bucket, long createdCommitID) {
      // no-op for tests
    }

    @Override
    public FilenameGenerator getGenerator() {
      return gen;
    }

    @Override
    public boolean checkDiskSpace(File file, int toWrite, int bufferSize) {
      return true; // Always allow in tests
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("storeTo_and_restoreRAFFrom_roundTrip_expectReadable")
  void storeTo_and_restoreRAFFrom_roundTrip_expectReadable(EncryptedRandomAccessBufferType type)
      throws Exception {
    // Arrange the underlying file-backed buffer so it can be restored from the stream
    File file = new File(tmpDir, "underlying.dat");
    int payload = 200;
    try (FileRandomAccessBuffer fab =
        new FileRandomAccessBuffer(file, type.headerLen + payload, false)) {
      MasterSecret secret = deterministicSecret();
      try (EncryptedRandomAccessBuffer raf =
          new EncryptedRandomAccessBuffer(type, fab, secret, true)) {
        byte[] data = new byte[payload];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 7 + 1);
        raf.pwrite(0, data, 0, data.length);

        // Persist wrapper
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(bos)) {
          raf.storeTo(dos);
        }

        // Restore via BucketTools (consumes wrapper magic then type, then underlying)
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        DataInputStream dis = new DataInputStream(bis);
        FilenameGenerator fg = new FilenameGenerator(new Random(1234L), false, tmpDir, "tst-");
        PersistentFileTracker pft = new DummyTracker(tmpDir, fg);
        LockableRandomAccessBuffer restored = BucketTools.restoreRAFFrom(dis, fg, pft, secret);

        byte[] out = new byte[payload];
        restored.pread(0, out, 0, out.length);
        assertArrayEquals(data, out);

        // Equality and hashCode should match for logically same wrapper
        assertEquals(raf, restored);
        assertEquals(raf.hashCode(), restored.hashCode());

        restored.close();
        restored.free();
      }
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("restoreRAFFrom_whenWrongSecret_expectResumeFailedException")
  void restoreRAFFrom_whenWrongSecret_expectResumeFailedException(
      EncryptedRandomAccessBufferType type)
      throws IOException, java.security.GeneralSecurityException {
    // Arrange
    File file = new File(tmpDir, "underlying2.dat");
    int payload = 64;
    MasterSecret secret = deterministicSecret();
    try (FileRandomAccessBuffer fab =
        new FileRandomAccessBuffer(file, type.headerLen + payload, false)) {
      try (EncryptedRandomAccessBuffer raf =
          new EncryptedRandomAccessBuffer(type, fab, secret, true)) {
        raf.pwrite(0, new byte[payload], 0, payload);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(bos)) {
          raf.storeTo(dos);
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        DataInputStream dis = new DataInputStream(bis);
        FilenameGenerator fg = new FilenameGenerator(new Random(5678L), false, tmpDir, "t-");
        PersistentFileTracker pft = new DummyTracker(tmpDir, fg);

        // Act + Assert (wrong secret)
        MasterSecret wrong = new MasterSecret(new byte[64]);
        assertThrows(
            ResumeFailedException.class, () -> BucketTools.restoreRAFFrom(dis, fg, pft, wrong));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("restoreRAFFrom_whenWrongSecret_onWindows_releasesUnderlyingFileHandle")
  void restoreRAFFrom_whenWrongSecret_onWindows_releasesUnderlyingFileHandle(
      EncryptedRandomAccessBufferType type) throws Exception {
    assumeTrue(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));

    // Arrange
    File file = new File(tmpDir, "underlying-win-" + type.name() + ".dat");
    int payload = 64;
    MasterSecret secret = deterministicSecret();
    byte[] persisted;
    try (FileRandomAccessBuffer fab =
            new FileRandomAccessBuffer(file, type.headerLen + payload, false);
        EncryptedRandomAccessBuffer raf =
            new EncryptedRandomAccessBuffer(type, fab, secret, true)) {
      raf.pwrite(0, new byte[payload], 0, payload);

      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try (DataOutputStream dos = new DataOutputStream(bos)) {
        raf.storeTo(dos);
      }
      persisted = bos.toByteArray();
    }

    FilenameGenerator fg = new FilenameGenerator(new Random(9123L), false, tmpDir, "t-win-");
    PersistentFileTracker pft = new DummyTracker(tmpDir, fg);
    MasterSecret wrong = new MasterSecret(new byte[64]);

    // Act + Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(persisted))) {
      assertThrows(
          ResumeFailedException.class, () -> BucketTools.restoreRAFFrom(dis, fg, pft, wrong));
    }

    assertTrue(file.delete(), "Expected failed restore to leave no open file handle");
  }

  // ---------------- Java serialization ----------------

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName(
      "serialize/deserialize round-trip restores underlying and remains readable after onResume")
  void serializeRoundTrip_restoresUnderlying_andReadableAfterOnResume(
      EncryptedRandomAccessBufferType type) throws Exception {
    int payload = 1024;

    try (LockableRandomAccessBuffer underlying =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload)) {
      MasterSecret secret = deterministicSecret();

      EncryptedRandomAccessBuffer raf =
          new EncryptedRandomAccessBuffer(type, underlying, secret, true);
      byte[] data = new byte[payload];
      new Random(1234L).nextBytes(data);
      raf.pwrite(0, data, 0, data.length);

      // Serialize
      byte[] bytes;
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
          ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        oos.writeObject(raf);
        oos.flush();
        bytes = bos.toByteArray();
      }

      // Deserialize and use try-with-resources to ensure close()
      try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
          EncryptedRandomAccessBuffer restored = (EncryptedRandomAccessBuffer) ois.readObject()) {
        assertNotNull(restored);
        // Supply persistent secret and verify readability
        CryptoResumeContext ctx = Mockito.mock(CryptoResumeContext.class);
        Mockito.when(ctx.getPersistentMasterSecret()).thenReturn(secret);
        restored.onResume(ctx);

        byte[] out = new byte[payload];
        restored.pread(0, out, 0, out.length);
        assertArrayEquals(data, out);

        restored.free();
      }

      raf.close();
    }
  }

  @ParameterizedTest
  @MethodSource("types")
  @DisplayName("deserialize does not consume following object in stream")
  void deserialize_doesNotConsumeFollowingObject(EncryptedRandomAccessBufferType type)
      throws Exception {
    int payload = 128;
    try (LockableRandomAccessBuffer underlying =
        new network.crypta.support.io.ByteArrayRandomAccessBuffer(type.headerLen + payload)) {
      MasterSecret secret = deterministicSecret();
      EncryptedRandomAccessBuffer raf =
          new EncryptedRandomAccessBuffer(type, underlying, secret, true);
      byte[] data = new byte[payload];
      for (int i = 0; i < data.length; i++) data[i] = (byte) i;
      raf.pwrite(0, data, 0, data.length);

      // Write the ERAB followed by an Integer
      byte[] bytes;
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
          ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        oos.writeObject(raf);
        oos.writeObject(424242);
        oos.flush();
        bytes = bos.toByteArray();
      }

      try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
          EncryptedRandomAccessBuffer restored = (EncryptedRandomAccessBuffer) ois.readObject()) {
        CryptoResumeContext ctx = Mockito.mock(CryptoResumeContext.class);
        Mockito.when(ctx.getPersistentMasterSecret()).thenReturn(secret);
        restored.onResume(ctx);
        byte[] out = new byte[payload];
        restored.pread(0, out, 0, out.length);
        assertArrayEquals(data, out);

        Object next = ois.readObject();
        assertInstanceOf(Integer.class, next);
        assertEquals(424242, ((Integer) next).intValue());

        restored.free();
      }
    }
  }
}

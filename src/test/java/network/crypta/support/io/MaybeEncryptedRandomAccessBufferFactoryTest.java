package network.crypta.support.io;

import java.io.IOException;
import java.util.function.Supplier;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests for {@link MaybeEncryptedRandomAccessBufferFactory}.
 *
 * <p>Strategy: use a spy/mock underlying {@link LockableRandomAccessBufferFactory} and {@link
 * ByteArrayRandomAccessBufferFactory} to verify delegation, padding, and encryption wrapping
 * without touching disk. For encryption paths, use a deterministic {@link MasterSecret}.
 */
@SuppressWarnings("java:S100") // allow method_whenCondition_expectOutcome naming for tests
class MaybeEncryptedRandomAccessBufferFactoryTest {

  @BeforeAll
  static void loadJceProvider() {
    // Ensure BouncyCastle and friends are registered so CHACHA/HMAC are available.
    network.crypta.crypt.JceLoader.dumpLoaded();
  }

  private static MasterSecret deterministicSecret() {
    byte[] s = new byte[64];
    for (int i = 0; i < s.length; i++) s[i] = (byte) i;
    return new MasterSecret(s);
  }

  private ByteArrayRandomAccessBufferFactory underlyingArrayFactory;

  @BeforeEach
  void setUp() {
    underlyingArrayFactory = Mockito.spy(new ByteArrayRandomAccessBufferFactory());
  }

  // Test helper factory to record arguments without invoking Mockito.verify(makeRAF(...)).
  private static final class RecordingFactory implements LockableRandomAccessBufferFactory {
    long lastLongSize = Long.MIN_VALUE;
    boolean longCalled;
    Object[] lastBytesArgs;
    boolean bytesCalled;
    private final Supplier<LockableRandomAccessBuffer> longSupplier;
    private final ByteArrayRandomAccessBufferFactory delegate =
        new ByteArrayRandomAccessBufferFactory();

    RecordingFactory() {
      this(null);
    }

    RecordingFactory(Supplier<LockableRandomAccessBuffer> longSupplier) {
      this.longSupplier = longSupplier;
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
      this.longCalled = true;
      this.lastLongSize = size;
      if (longSupplier != null) return longSupplier.get();
      return delegate.makeRAF(size);
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(
        byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
      this.bytesCalled = true;
      this.lastBytesArgs = new Object[] {initialContents, offset, size, readOnly};
      return delegate.makeRAF(initialContents, offset, size, readOnly);
    }
  }

  private static void openAndClose(MaybeEncryptedRandomAccessBufferFactory factory, long size)
      throws IOException {
    LockableRandomAccessBuffer raf = factory.makeRAF(size);
    if (raf != null) {
      raf.close();
    }
  }

  private static void openAndClose(
      MaybeEncryptedRandomAccessBufferFactory factory, byte[] initialContents, int offset, int size)
      throws IOException {
    LockableRandomAccessBuffer raf = factory.makeRAF(initialContents, offset, size, false);
    if (raf != null) {
      raf.close();
    }
  }

  // ---------------------------- makeRAF(long) ----------------------------

  @ParameterizedTest(name = "encrypt={0}, secretSet={1}")
  @CsvSource({"false,false", "false,true", "true,false"})
  @DisplayName("makeRAF(long)_whenNotEncrypting_expectDelegateAndRawBuffer")
  void makeRAF_whenNotEncrypting_expectDelegateAndRawBuffer(boolean encrypt, boolean secretSet)
      throws IOException {
    // Arrange
    RecordingFactory recorder = new RecordingFactory();
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(recorder, encrypt);
    if (secretSet) factory.setMasterSecret(deterministicSecret());
    long reqSize = 1234L;

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(reqSize)) {
      // Assert
      assertTrue(recorder.longCalled);
      assertEquals(reqSize, recorder.lastLongSize);
      assertThat(raf, instanceOf(ByteArrayRandomAccessBuffer.class));
      assertEquals(reqSize, raf.size());
    }
  }

  @Test
  @DisplayName("makeRAF(long)_whenEncryptingWithSecretAndZeroSize_expectPaddedEncrypted")
  void makeRAF_whenEncryptingWithSecretAndZeroSize_expectPaddedEncrypted() throws IOException {
    // Arrange
    RecordingFactory recorder = new RecordingFactory();
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(recorder, true);
    factory.setMasterSecret(deterministicSecret());
    long headerLen = TempBucketFactory.CRYPT_TYPE.headerLen;
    long expectedPadded =
        PaddedEphemerallyEncryptedBucket.paddedLength(
            headerLen, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(0)) {
      // Assert
      assertTrue(recorder.longCalled);
      assertEquals(expectedPadded, recorder.lastLongSize);
      assertThat(raf, instanceOf(EncryptedRandomAccessBuffer.class));
      assertEquals(0, raf.size(), "logical size equals requested size");
    }
  }

  @Test
  @DisplayName(
      "makeRAF(long)_whenEncryptingWithSecretAndExactPadBoundary_expectEncryptedNoExtraPad")
  void makeRAF_whenEncryptingWithSecretAndExactPadBoundary_expectEncryptedNoExtraPad()
      throws IOException {
    // Arrange: choose size so (size + headerLen) == MIN_PADDED_SIZE
    long headerLen = TempBucketFactory.CRYPT_TYPE.headerLen;
    long min = PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE;
    long reqSize = min - headerLen; // ensures no PaddedRandomAccessBuffer wrapper is needed
    assertTrue(reqSize >= 0, "sanity");

    RecordingFactory recorder = new RecordingFactory();
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(recorder, true);
    factory.setMasterSecret(deterministicSecret());

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(reqSize)) {
      // Assert
      assertTrue(recorder.longCalled);
      assertEquals(min, recorder.lastLongSize);
      assertThat(raf, instanceOf(EncryptedRandomAccessBuffer.class));
      assertEquals(reqSize, raf.size());
    }
  }

  @Test
  @DisplayName("makeRAF(long)_whenEncrypted_writesHeaderToUnderlying")
  void makeRAF_whenEncrypted_writesHeaderToUnderlying() throws IOException {
    // Arrange: mock underlying RAF to observe header write via PaddedRandomAccessBuffer
    LockableRandomAccessBuffer underlyingRaf = mock(LockableRandomAccessBuffer.class);
    when(underlyingRaf.size()).thenReturn(2048L);

    RecordingFactory recorder = new RecordingFactory(() -> underlyingRaf);

    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(recorder, true);
    factory.setMasterSecret(deterministicSecret());
    int headerLen = TempBucketFactory.CRYPT_TYPE.headerLen;

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(0L)) {
      // Assert: encrypted wrapper returned and header written at offset 0
      assertThat(raf, instanceOf(EncryptedRandomAccessBuffer.class));
      long expected =
          PaddedEphemerallyEncryptedBucket.paddedLength(
              headerLen, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);
      assertTrue(recorder.longCalled);
      assertEquals(expected, recorder.lastLongSize);
      verify(underlyingRaf, atLeastOnce())
          .pwrite(eq(0L), argThat(b -> b != null && b.length == headerLen), eq(0), eq(headerLen));
    }
  }

  @Test
  @DisplayName("makeRAF(long)_whenUnderlyingTooSmall_expectIOException")
  void makeRAF_whenUnderlyingTooSmall_expectIOException() throws Exception {
    // Arrange: choose size s.t. realSize == MIN_PADDED_SIZE so no PaddedRandomAccessBuffer is used
    long headerLen = TempBucketFactory.CRYPT_TYPE.headerLen;
    long min = PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE;
    long reqSize = min - headerLen;

    // Underlying RAF claims to be smaller than header, which forces ERAB ctor to throw
    LockableRandomAccessBuffer tiny = mock(LockableRandomAccessBuffer.class);
    when(tiny.size()).thenReturn(1L);
    doThrow(new UnsupportedOperationException()).when(tiny).lockOpen();

    LockableRandomAccessBufferFactory mockFactory = mock(LockableRandomAccessBufferFactory.class);
    try {
      when(mockFactory.makeRAF(anyLong())).thenReturn(tiny);
    } catch (IOException e) {
      fail(e);
    }

    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(mockFactory, true);
    factory.setMasterSecret(deterministicSecret());

    // Act + Assert
    assertThrows(IOException.class, () -> openAndClose(factory, reqSize));
  }

  // ---------------------------- makeRAF(byte[], ..) ----------------------------

  @Test
  @DisplayName("makeRAF(bytes)_whenEncryptionDisabled_expectDelegateToUnderlying")
  void makeRAF_withInitialContents_whenEncryptionDisabled_expectDelegateToUnderlying()
      throws IOException {
    // Arrange
    RecordingFactory recorder = new RecordingFactory();
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(recorder, false);
    byte[] data = {0, 1, 2, 3, 4};

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(data, 1, 3, false)) {
      // Assert
      assertTrue(recorder.bytesCalled);
      assertArrayEquals(new Object[] {data, 1, 3, false}, recorder.lastBytesArgs);
      assertThat(raf, instanceOf(ByteArrayRandomAccessBuffer.class));

      byte[] out = new byte[3];
      raf.pread(0, out, 0, 3);
      assertArrayEquals(new byte[] {1, 2, 3}, out);
    }
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenEncryptionEnabled_expectEncryptedAndDataWritten")
  void makeRAF_withInitialContents_whenEncryptionEnabled_expectEncryptedAndDataWritten()
      throws IOException {
    // Arrange
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, true);
    factory.setMasterSecret(deterministicSecret());
    byte[] data = {9, 8, 7, 6};

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(data, 1, 2, false)) {
      // Assert
      assertThat(raf, instanceOf(EncryptedRandomAccessBuffer.class));
      assertEquals(2, raf.size());

      byte[] out = new byte[2];
      raf.pread(0, out, 0, 2);
      assertArrayEquals(new byte[] {8, 7}, out);
    }
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenReadOnlyAndEncrypted_expectReadOnlyWrapper")
  void makeRAF_withInitialContents_whenReadOnlyAndEncrypted_expectReadOnlyWrapper()
      throws IOException {
    // Arrange
    MaybeEncryptedRandomAccessBufferFactory factory =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, true);
    factory.setMasterSecret(deterministicSecret());
    byte[] data = {10, 11, 12, 13};

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(data, 1, 3, true)) {
      // Assert: writing must fail, reading must succeed
      byte[] out = new byte[3];
      raf.pread(0, out, 0, 3);
      assertArrayEquals(new byte[] {11, 12, 13}, out);
      assertThrows(IOException.class, () -> raf.pwrite(0, new byte[] {1, 2, 3}, 0, 3));
    }
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenNullInitialContents_expectNullPointerException")
  void makeRAF_withInitialContents_whenNull_expectNullPointerException() {
    // Arrange
    MaybeEncryptedRandomAccessBufferFactory disabled =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, false);
    MaybeEncryptedRandomAccessBufferFactory enabled =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, true);
    enabled.setMasterSecret(deterministicSecret());

    // Act + Assert (disabled path delegates to Arrays#copyOfRange -> NPE)
    assertThrows(NullPointerException.class, () -> openAndClose(disabled, null, 0, 1));
    // Act + Assert (enabled path writes via pwrite -> NPE)
    assertThrows(NullPointerException.class, () -> openAndClose(enabled, null, 0, 1));
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenNegativeSize_expectIllegalArgumentException")
  void makeRAF_withInitialContents_whenNegativeSize_expectIllegalArgumentException() {
    // Arrange
    MaybeEncryptedRandomAccessBufferFactory disabled =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, false);
    MaybeEncryptedRandomAccessBufferFactory enabled =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, true);
    enabled.setMasterSecret(deterministicSecret());
    byte[] data = {1, 2, 3};

    // Act + Assert: disabled branch validates 'size' directly; encrypted branch
    // creates a padded RAF then fails ERAB init with IOException
    assertThrows(IllegalArgumentException.class, () -> openAndClose(disabled, data, 0, -1));
    assertThrows(IOException.class, () -> openAndClose(enabled, data, 0, -1));
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenOffsetOutOfBounds_expectArrayIndexOutOfBounds")
  void makeRAF_withInitialContents_whenOffsetOutOfBounds_expectArrayIndexOutOfBounds() {
    // Arrange
    MaybeEncryptedRandomAccessBufferFactory disabled =
        new MaybeEncryptedRandomAccessBufferFactory(underlyingArrayFactory, false);
    byte[] data = {1, 2, 3};

    // Act + Assert: copyOfRange validates bounds (offset beyond array end)
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> openAndClose(disabled, data, 4, 1));
  }

  // ---------------------------- setEncryption ----------------------------

  // No longer propagates to pooled factory; encryption is handled at this layer by wrapping.
}

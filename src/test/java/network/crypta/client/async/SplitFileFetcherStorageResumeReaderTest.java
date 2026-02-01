package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "resource"})
@ExtendWith(MockitoExtension.class)
class SplitFileFetcherStorageResumeReaderTest {

  @Test
  void readParsedSettings_whenFooterValid_returnsParsedSettings() throws Exception {
    int checksumLength = 4;
    int basicSettingsLength = 32;
    long rafLength = 200L;
    ResumeLayout layout =
        ResumeLayout.create(
            rafLength,
            basicSettingsLength,
            checksumLength,
            0,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, rafLength);

    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    when(checksumChecker.checkChecksum(any(byte[].class), anyInt(), anyInt(), any(byte[].class)))
        .thenReturn(true);

    ParsedBasicSettings expected =
        new ParsedBasicSettings(
            SplitfileAlgorithm.ONION_STANDARD,
            (byte) 0,
            null,
            100L,
            200L,
            new ClientMetadata("text/plain"),
            List.of(COMPRESSOR_TYPE.GZIP),
            10L,
            20L,
            30L,
            40L,
            50L,
            60L,
            70L,
            80L,
            CompatibilityMode.COMPAT_1250,
            2,
            3,
            4,
            0,
            new DataInputStream(new ByteArrayInputStream(new byte[0])));

    try (MockedStatic<SplitFileFetcherStorageSettingsCodec> mocked =
        mockStatic(SplitFileFetcherStorageSettingsCodec.class)) {
      ArgumentCaptor<byte[]> bufferCaptor = ArgumentCaptor.forClass(byte[].class);
      mocked
          .when(
              () ->
                  SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                      bufferCaptor.capture(),
                      eq(layout.basicSettingsOffset),
                      eq(true),
                      eq(rafLength)))
          .thenReturn(expected);

      ParsedBasicSettings result =
          SplitFileFetcherStorageResumeReader.readParsedSettings(
              raf, checksumChecker, checksumLength, rafLength, true);

      assertSame(expected, result);
      assertEquals(layout.basicSettingsLength, bufferCaptor.getValue().length);
      assertEquals(layout.payloadSignature, bufferCaptor.getValue()[0]);
      verify(checksumChecker).checkChecksum(any(byte[].class), eq(0), eq(14), any(byte[].class));
      verify(checksumChecker)
          .checkChecksum(any(byte[].class), eq(0), eq(basicSettingsLength), any(byte[].class));
    }
  }

  @Test
  void readParsedSettings_whenTooShort_throwsStorageFormatException() {
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, 4, 7L, false));
  }

  @Test
  void readParsedSettings_whenMagicMismatch_throwsStorageFormatException() throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L, 16, 4, 0, ChecksumChecker.CHECKSUM_CRC, SplitFileFetcherStorage.VERSION, 0L);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  @Test
  void readParsedSettings_whenVersionMismatch_throwsStorageFormatException() throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L,
            16,
            4,
            0,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION + 1,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  @Test
  void readParsedSettings_whenChecksumTypeUnknown_throwsStorageFormatException() throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L, 16, 4, 0, 99, SplitFileFetcherStorage.VERSION, SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  @Test
  void readParsedSettings_whenFlagsNonZero_throwsStorageFormatException() throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L,
            16,
            4,
            42,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  @Test
  void readParsedSettings_whenLengthChecksumFails_throwsStorageFormatException() throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L,
            32,
            4,
            0,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    when(checksumChecker.checkChecksum(any(byte[].class), anyInt(), anyInt(), any(byte[].class)))
        .thenAnswer(invocation -> !invocation.getArgument(2).equals(14));

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  @Test
  void readParsedSettings_whenBasicSettingsLengthTooLarge_throwsStorageFormatException()
      throws Exception {
    int checksumLength = 4;
    int basicSettingsLength = 1_048_577;
    long rafLength = basicSettingsLength + 200L;
    ResumeLayout layout =
        ResumeLayout.create(
            rafLength,
            basicSettingsLength,
            checksumLength,
            0,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    when(checksumChecker.checkChecksum(any(byte[].class), anyInt(), anyInt(), any(byte[].class)))
        .thenReturn(true);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, checksumLength, rafLength, false));
  }

  @Test
  void readParsedSettings_whenBasicSettingsChecksumInvalid_throwsStorageFormatException()
      throws Exception {
    ResumeLayout layout =
        ResumeLayout.create(
            200L,
            32,
            4,
            0,
            ChecksumChecker.CHECKSUM_CRC,
            SplitFileFetcherStorage.VERSION,
            SplitFileFetcherStorage.END_MAGIC);
    LockableRandomAccessBuffer raf = mockRaf(layout.data, layout.rafLength);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    when(checksumChecker.checkChecksum(any(byte[].class), anyInt(), anyInt(), any(byte[].class)))
        .thenAnswer(invocation -> invocation.getArgument(2).equals(14));

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageResumeReader.readParsedSettings(
                raf, checksumChecker, layout.checksumLength, layout.rafLength, false));
  }

  private static LockableRandomAccessBuffer mockRaf(byte[] data, long length) throws Exception {
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    lenient().when(raf.size()).thenReturn(length);
    doAnswer(
            invocation -> {
              long fileOffset = invocation.getArgument(0);
              byte[] buffer = invocation.getArgument(1);
              int bufOffset = invocation.getArgument(2);
              int readLength = invocation.getArgument(3);
              System.arraycopy(data, (int) fileOffset, buffer, bufOffset, readLength);
              return null;
            })
        .when(raf)
        .pread(anyLong(), any(byte[].class), anyInt(), anyInt());
    return raf;
  }

  private static final class ResumeLayout {
    private final byte[] data;
    private final long rafLength;
    private final int basicSettingsLength;
    private final int checksumLength;
    private final long basicSettingsOffset;
    private final byte payloadSignature;

    private ResumeLayout(
        byte[] data,
        long rafLength,
        int basicSettingsLength,
        int checksumLength,
        long basicSettingsOffset,
        byte payloadSignature) {
      this.data = data;
      this.rafLength = rafLength;
      this.basicSettingsLength = basicSettingsLength;
      this.checksumLength = checksumLength;
      this.basicSettingsOffset = basicSettingsOffset;
      this.payloadSignature = payloadSignature;
    }

    private static ResumeLayout create(
        long rafLength,
        int basicSettingsLength,
        int checksumLength,
        int flags,
        int checksumType,
        int version,
        long magic) {
      byte[] data = new byte[(int) rafLength];
      byte payloadSignature = (byte) 0x5A;
      byte[] payload = new byte[basicSettingsLength];
      Arrays.fill(payload, payloadSignature);
      long basicSettingsOffset = rafLength - (18 + 4 + checksumLength * 2L + basicSettingsLength);
      System.arraycopy(payload, 0, data, (int) basicSettingsOffset, basicSettingsLength);
      int checksumOffset = (int) (basicSettingsOffset + basicSettingsLength);
      for (int i = 0; i < checksumLength; i++) {
        data[checksumOffset + i] = (byte) 0x1;
      }
      writeInt(data, (int) (rafLength - (22 + checksumLength)), basicSettingsLength);
      for (int i = 0; i < checksumLength; i++) {
        data[(int) (rafLength - (18 + checksumLength)) + i] = (byte) 0x2;
      }
      writeInt(data, (int) (rafLength - 18), flags);
      writeShort(data, (int) (rafLength - 14), (short) checksumType);
      writeInt(data, (int) (rafLength - 12), version);
      writeLong(data, (int) (rafLength - 8), magic);
      return new ResumeLayout(
          data,
          rafLength,
          basicSettingsLength,
          checksumLength,
          basicSettingsOffset,
          payloadSignature);
    }
  }

  private static void writeInt(byte[] data, int offset, int value) {
    byte[] encoded = ByteBuffer.allocate(4).putInt(value).array();
    System.arraycopy(encoded, 0, data, offset, 4);
  }

  private static void writeShort(byte[] data, int offset, short value) {
    byte[] encoded = ByteBuffer.allocate(2).putShort(value).array();
    System.arraycopy(encoded, 0, data, offset, 2);
  }

  private static void writeLong(byte[] data, int offset, long value) {
    byte[] encoded = ByteBuffer.allocate(8).putLong(value).array();
    System.arraycopy(encoded, 0, data, offset, 8);
  }
}

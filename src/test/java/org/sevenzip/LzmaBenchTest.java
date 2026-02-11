package org.sevenzip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LzmaBenchTest {
  private java.io.PrintStream originalOut;
  private ByteArrayOutputStream outContent;
  private PrintStream testOut;

  @BeforeEach
  void setUpStreams() {
    originalOut = System.out;
    outContent = new ByteArrayOutputStream();
    testOut = new PrintStream(outContent, false, StandardCharsets.UTF_8);
    System.setOut(testOut);
  }

  @AfterEach
  void restoreStreams() {
    if (testOut != null) {
      testOut.flush();
      testOut.close();
    }
    System.setOut(originalOut);
  }

  @Test
  void getLogSize_whenExactPowerOfTwo_returnsBaseEncoded() {
    int logSize = LzmaBench.getLogSize(1 << 18);

    assertEquals(18 * 256, logSize);
  }

  @Test
  void getLogSize_whenWithinBucket_returnsOffsetEncoded() {
    int size = (1 << 18) + 1024; // j = 1 at i = 18

    int logSize = LzmaBench.getLogSize(size);

    assertEquals((18 * 256) + 1, logSize);
  }

  @Test
  void myMultDiv64_whenElapsedZero_usesOneAsDivisor() {
    long result = LzmaBench.myMultDiv64(500, 0);

    assertEquals(500_000L, result);
  }

  @Test
  void getCompressRating_withBaselineInputs_returnsExpectedValue() {
    long rating = LzmaBench.getCompressRating(1 << 18, 50, 1_000);

    assertEquals(21_200_000L, rating);
  }

  @Test
  void getDecompressRating_withInAndOutSizes_returnsExpectedValue() {
    long rating = LzmaBench.getDecompressRating(40, 2_000, 500);

    assertEquals(3_750_000L, rating);
  }

  @Test
  void myOutputStream_whenExceedingCapacity_throwsIOException() throws Exception {
    try (LzmaBench.MyOutputStream stream = new LzmaBench.MyOutputStream(new byte[1])) {
      byte[] data = new byte[] {1, 2};
      assertThrows(IOException.class, () -> stream.write(data));
    }
  }

  @Test
  void myOutputStream_writeWithInvalidRange_throwsIndexOutOfBounds() throws Exception {
    try (LzmaBench.MyOutputStream stream = new LzmaBench.MyOutputStream(new byte[4])) {
      assertThrows(IndexOutOfBoundsException.class, () -> stream.write(new byte[2], 0, 3));
    }
  }

  @Test
  void myInputStream_readSequence_returnsBytesAndMinusOne() throws Exception {
    byte[] data = new byte[] {1, 2, 3};
    try (LzmaBench.MyInputStream stream = new LzmaBench.MyInputStream(data, 3)) {
      assertEquals(1, stream.read());
      assertEquals(2, stream.read());
      assertEquals(3, stream.read());
      assertEquals(-1, stream.read());
    }
  }

  @Test
  void myInputStream_readWithInvalidRange_throwsIndexOutOfBounds() throws Exception {
    try (LzmaBench.MyInputStream stream = new LzmaBench.MyInputStream(new byte[2], 2)) {
      assertThrows(IndexOutOfBoundsException.class, () -> stream.read(new byte[1], 1, 1));
    }
  }

  @Test
  void cRandomGenerator_initResetsSequence() {
    LzmaBench.CRandomGenerator generator = new LzmaBench.CRandomGenerator();
    int first = generator.getRnd();
    generator.getRnd(); // advance state
    generator.init();

    int resetFirst = generator.getRnd();

    assertEquals(first, resetFirst);
  }

  @Test
  void benchRandomGenerator_generate_isDeterministic() {
    LzmaBench.CBenchRandomGenerator first = new LzmaBench.CBenchRandomGenerator();
    first.set(32);
    first.generate();

    LzmaBench.CBenchRandomGenerator second = new LzmaBench.CBenchRandomGenerator();
    second.set(32);
    second.generate();

    assertArrayEquals(first.buffer, second.buffer);
  }

  @Test
  void cProgressInfo_setProgress_setsTimeOnceWhenThresholdReached() {
    LzmaBench.CProgressInfo progressInfo = new LzmaBench.CProgressInfo();
    progressInfo.approvedStart = 10;
    progressInfo.init();

    progressInfo.setProgress(5, 0); // below threshold
    assertEquals(0, progressInfo.inSize);
    assertEquals(0, progressInfo.time);

    progressInfo.setProgress(15, 0); // meets threshold
    long recordedTime = progressInfo.time;
    assertEquals(15, progressInfo.inSize);
    assertTrue(recordedTime > 0);

    progressInfo.setProgress(20, 0); // should not update again
    assertEquals(recordedTime, progressInfo.time);
  }

  @Test
  void lzmaBenchmark_whenDictionaryTooSmall_printsErrorAndReturns() throws Exception {
    LzmaBench.lzmaBenchmark(1, (1 << 18) - 1);

    String output = outContent.toString(StandardCharsets.UTF_8);
    assertTrue(output.contains("Error: dictionary size for benchmark must be >= 18 (256 KB)"));
  }

  @Test
  void lzmaBenchmark_withMocks_runsSingleIterationAndPrintsSummary() throws Exception {
    int dictionarySize = 1 << 18;

    try (MockedConstruction<Encoder> encoderConstruction =
            Mockito.mockConstruction(
                Encoder.class,
                (mock, _) -> {
                  Mockito.when(mock.setDictionarySize(dictionarySize)).thenReturn(true);
                  Mockito.doAnswer(
                          invocation -> {
                            OutputStream os = invocation.getArgument(0);
                            os.write(new byte[] {1});
                            return null;
                          })
                      .when(mock)
                      .writeCoderProperties(Mockito.any(OutputStream.class));
                  Mockito.doAnswer(
                          invocation -> {
                            LzmaBench.CProgressInfo info = invocation.getArgument(2);
                            info.setProgress(dictionarySize, 0);
                            return null;
                          })
                      .when(mock)
                      .code(
                          Mockito.any(java.io.InputStream.class),
                          Mockito.any(OutputStream.class),
                          Mockito.any(LzmaBench.CProgressInfo.class));
                });
        MockedConstruction<Decoder> decoderConstruction =
            Mockito.mockConstruction(
                Decoder.class,
                (mock, _) ->
                    Mockito.when(
                            mock.code(
                                Mockito.any(java.io.InputStream.class),
                                Mockito.any(OutputStream.class),
                                Mockito.anyLong()))
                        .thenReturn(true));
        MockedConstruction<CRC> crcConstruction =
            Mockito.mockConstruction(
                CRC.class, (mock, _) -> Mockito.when(mock.getDigest()).thenReturn(123));
        MockedConstruction<LzmaBench.CrcOutStream> crcOutConstruction =
            Mockito.mockConstruction(
                LzmaBench.CrcOutStream.class,
                (mock, _) -> Mockito.when(mock.getDigest()).thenReturn(123))) {
      LzmaBench.lzmaBenchmark(1, dictionarySize);

      String output = outContent.toString(StandardCharsets.UTF_8);
      assertTrue(output.contains("Compressing"));
      assertTrue(output.contains("Decompressing"));
      assertTrue(output.contains("Average"));

      Encoder encoderMock = encoderConstruction.constructed().getFirst();
      Decoder decoderMock = decoderConstruction.constructed().getFirst();
      assertEquals(1, crcConstruction.constructed().size());
      assertEquals(1, crcOutConstruction.constructed().size());

      Mockito.verify(encoderMock).setDictionarySize(dictionarySize);
      Mockito.verify(decoderMock).setDecoderProperties(Mockito.any(byte[].class));
    }
  }
}

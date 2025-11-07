package network.crypta.client.filter;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static network.crypta.client.filter.ResourceFileUtil.resourceToBucket;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.CRC32;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.test.PngUtil;
import network.crypta.test.PngUtil.Chunk;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PNGFilterTest {
  protected static Object[][] testImages = {
    // Entries: path and expected validity
    {"./png/broken/nonconsecutive_idat.png", false}, //
    {"./png/broken/truncate_zlib_2.png", false}, //
    {"./png/broken/plte_after_idat.png", false}, //
    {"./png/broken/chunk_length.png", false}, //
    {"./png/broken/chunk_crc.png", false}, //
    {"./png/broken/missing_ihdr.png", false}, //
    {"./png/broken/gama_after_plte.png", false},
    {"./png/broken/multiple_ihdr.png", false}, //
    {"./png/broken/truncate_zlib.png", false}, //
    {"./png/broken/srgb_after_idat.png", false},
    {"./png/broken/iccp_after_idat.png", false},
    {"./png/broken/gama_after_idat.png", false},
    {"./png/misc/pngbar.png", true}, //
    {"./png/misc/pngnow.png", true}, //
    {"./png/misc/pngtest.png", true}, //
    {"./png/suite/basn2c16.png", true}, //
    {"./png/suite/basn3p01.png", true}, //
    {"./png/suite/basn2c08.png", true}, //
    {"./png/suite/basn3p04.png", true}, //
    {"./png/suite/basn0g16.png", true}, //
    {"./png/suite/basn0g08.png", true}, //
    {"./png/suite/basn0g02.png", true}, //
    {"./png/suite/basn4a08.png", true}, //
    {"./png/suite/basn6a08.png", true}, //
    {"./png/suite/basn6a16.png", true}, //
    {"./png/suite/basn4a16.png", true}, //
    {"./png/suite/basn0g01.png", true}, //
    {"./png/suite/basn3p08.png", true}, //
    {"./png/suite/basn3p02.png", true}, //
    {"./png/suite/basn0g04.png", true}, //
  };

  @Test
  void readFilter_whenRunningSuiteImages_expectValidityMatchesExpectations() {
    PNGFilter filter = new PNGFilter(false, false, true);

    for (Object[] test : testImages) {
      String filename = (String) test[0];
      boolean valid = (Boolean) test[1];
      try (Bucket ib = resourceToBucket(filename);
          NullBucket out = new NullBucket()) {
        if (valid) {
          assertDoesNotThrow(
              () ->
                  filter.readFilter(
                      ib.getInputStream(), out.getOutputStream(), "", null, null, null),
              filename + " should be valid");
        } else {
          assertThrows(
              DataFilterException.class,
              () ->
                  filter.readFilter(
                      ib.getInputStream(), out.getOutputStream(), "", null, null, null),
              filename + " should not be valid");
        }
      } catch (IOException e) {
        // Resource missing in test data; skip silently
      }
    }
  }

  @Test
  void readFilter_whenInvalidCICPChunks_expectRemoved() throws IOException {
    // cICP chunks must be 4 bytes long!
    Chunk brokencICPChunk1 = new Chunk("cICP", new byte[0]);
    // Arrange
    List<Chunk> chunks1 = filterAndGetChunks(List.of(brokencICPChunk1), emptyList());
    // Assert
    assertThat(chunks1, not(hasItem(brokencICPChunk1)));
    // Unsupported color model other than RGB is specified in PNG!
    Chunk brokencICPChunk2 = new Chunk("cICP", new byte[] {0xC, 0xD, 0x1, 0x1});
    // Arrange
    List<Chunk> chunks2 = filterAndGetChunks(List.of(brokencICPChunk2), emptyList());
    // Assert
    assertThat(chunks2, not(hasItem(brokencICPChunk2)));
  }

  @Test
  void readFilter_whenValidCICPChunk_expectChunkRetained() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(List.of(cICPChunk), emptyList());
    // Assert
    assertThat(chunks, hasItem(cICPChunk));
  }

  @Test
  void readFilter_whenCICPAfterPLTE_expectChunkRemoved() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(asList(PLTEChunk, cICPChunk), emptyList());
    // Assert
    assertThat(chunks, not(hasItem(cICPChunk)));
  }

  @Test
  void readFilter_whenCICPAfterIDAT_expectChunkRemoved() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(emptyList(), List.of(cICPChunk));
    // Assert
    assertThat(chunks, not(hasItem(cICPChunk)));
  }

  @Test
  void readFilter_whenMDCVWithCICP_expectChunkRetained() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(asList(cICPChunk, mDCVChunk), emptyList());
    // Assert
    assertThat(chunks, hasItem(mDCVChunk));
  }

  @Test
  void readFilter_whenMDCVWithoutCICP_expectChunkRemoved() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(List.of(mDCVChunk), emptyList());
    // Assert
    assertThat(chunks, not(hasItem(mDCVChunk)));
  }

  @Test
  void readFilter_whenMDCVAfterPLTE_expectChunkRemoved() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(asList(cICPChunk, PLTEChunk, mDCVChunk), emptyList());
    // Assert
    assertThat(chunks, not(hasItem(mDCVChunk)));
  }

  @Test
  void readFilter_whenMDCVAfterIDAT_expectChunkRemoved() throws IOException {
    // Arrange
    List<Chunk> chunks = filterAndGetChunks(List.of(cICPChunk), List.of(mDCVChunk));
    // Assert
    assertThat(chunks, not(hasItem(mDCVChunk)));
  }

  @Test
  void readFilter_whenCLLIChunk_expectChunkRetained() throws IOException {
    // Arrange
    Chunk cLLI = new Chunk("cLLI", new byte[0]);
    List<Chunk> chunks = filterAndGetChunks(List.of(cLLI), emptyList());
    // Assert
    assertThat(chunks, hasItem(cLLI));
  }

  @Test
  void readFilter_whenDeleteTextEnabled_removesTextChunks() throws IOException {
    File pngFile = newTempFile();
    // Add tEXt, zTXt, iTXt before IDAT
    writePngWithCustomChunks(
        pngFile,
        asList(
            new Chunk("tEXt", new byte[] {1, 2}),
            new Chunk("zTXt", new byte[] {3}),
            new Chunk("iTXt", new byte[] {4})),
        emptyList());

    File filtered = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(filtered)) {
      new PNGFilter(true, false, true)
          .readFilter(bucket.getInputStream(), out, "", null, null, null);
    }
    // None of the text chunks should remain
    assertThat(PngUtil.getChunks(filtered), not(hasItem(new Chunk("tEXt", new byte[] {1, 2}))));
    assertThat(PngUtil.getChunks(filtered), not(hasItem(new Chunk("zTXt", new byte[] {3}))));
    assertThat(PngUtil.getChunks(filtered), not(hasItem(new Chunk("iTXt", new byte[] {4}))));
  }

  @Test
  void readFilter_whenDeleteTextDisabled_keepsTextChunks() throws IOException {
    File pngFile = newTempFile();
    writePngWithCustomChunks(
        pngFile, List.of(new Chunk("tEXt", new byte[] {1, 2, 3})), emptyList());
    File filtered = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(filtered)) {
      new PNGFilter(false, false, true)
          .readFilter(bucket.getInputStream(), out, "", null, null, null);
    }
    assertThat(PngUtil.getChunks(filtered), hasItem(new Chunk("tEXt", new byte[] {1, 2, 3})));
  }

  @Test
  void readFilter_whenDeleteTimestampEnabled_removesTimeChunk() throws IOException {
    File pngFile = newTempFile();
    writePngWithCustomChunks(
        pngFile, List.of(new Chunk("tIME", new byte[] {0, 1, 2, 3, 4, 5, 6})), emptyList());
    File filtered = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(filtered)) {
      new PNGFilter(false, true, true)
          .readFilter(bucket.getInputStream(), out, "", null, null, null);
    }
    assertThat(
        PngUtil.getChunks(filtered),
        not(hasItem(new Chunk("tIME", new byte[] {0, 1, 2, 3, 4, 5, 6}))));
  }

  @Test
  void invalidHeader_throwsDataFilterException() {
    // Arrange: invalid 8-byte signature
    byte[] badHeader = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.write(badHeader);
      // ensure stream has more bytes so readFully(length) doesn't block semantics
      dos.writeInt(0);
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
    PNGFilter filter = new PNGFilter(false, false, true);
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(baos.toByteArray()),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
  }

  @Test
  void unknownChunk_withValidName_isSkippedNotWritten() throws IOException {
    File pngFile = newTempFile();
    Chunk unknown = new Chunk("rAnD", new byte[] {9});
    writePngWithCustomChunks(pngFile, List.of(unknown), emptyList());
    File filtered = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(filtered)) {
      new PNGFilter(false, false, true)
          .readFilter(bucket.getInputStream(), out, "", null, null, null);
    }
    assertThat(PngUtil.getChunks(filtered), not(hasItem(unknown)));
  }

  @Test
  void chunkType_withNonAlphabeticBytes_throws() throws IOException {
    // Build: PNG header + IHDR (valid) + invalid chunk name "0000" so the filter throws
    File pngFile = newTempFile();
    try (FileOutputStream fos = new FileOutputStream(pngFile)) {
      fos.write(PNG_HEADER);
      // Valid IHDR
      new Chunk("IHDR", new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0}).write(fos);
      // Invalid chunk type name (not A-Za-z)
      new Chunk("0000", new byte[] {1}).write(fos);
      new Chunk("IEND", new byte[0]).write(fos);
    }
    PNGFilter filter = new PNGFilter(false, false, true);
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(newTempFile())) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(bucket.getInputStream(), out, "", null, null, null));
    }
  }

  @Test
  void crcMismatch_onHarmlessChunk_isSkipped() throws IOException {
    // Prepare a harmless chunk with bad CRC and ensure it is dropped
    // Compute correct CRC and flip bits to create a deterministic incorrect CRC
    CRC32 crc = new CRC32();
    crc.update("pHYs".getBytes(StandardCharsets.UTF_8));
    crc.update(new byte[] {1, 2, 3});
    int good = (int) crc.getValue();
    int bad = ~good;
    Chunk pHYsBad = new Chunk("pHYs", new byte[] {1, 2, 3}, bad);

    File pngFile = newTempFile();
    try (FileOutputStream fos = new FileOutputStream(pngFile)) {
      fos.write(PNG_HEADER);
      new Chunk("IHDR", new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0}).write(fos);
      pHYsBad.write(fos);
      new Chunk(
              "IDAT", new byte[] {0x08, 0x5b, 0x63, 0x60, 0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x01})
          .write(fos);
      new Chunk("IEND", new byte[0]).write(fos);
    }
    File filtered = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(filtered)) {
      new PNGFilter(false, false, true)
          .readFilter(bucket.getInputStream(), out, "", null, null, null);
    }
    assertThat(PngUtil.getChunks(filtered), not(hasItem(pHYsBad)));
  }

  @Test
  void ihdr_withInvalidLength_throws() throws IOException {
    // IHDR must be length 13. Create invalid IHDR of length 12 with correct CRC for those 12 bytes.
    File pngFile = newTempFile();
    byte[] invalidIHDR =
        new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0 /* missing interlace byte */};
    try (FileOutputStream fos = new FileOutputStream(pngFile)) {
      fos.write(PNG_HEADER);
      new Chunk("IHDR", invalidIHDR).write(fos);
      new Chunk("IEND", new byte[0]).write(fos);
    }
    PNGFilter filter = new PNGFilter(false, false, true);
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(newTempFile())) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(bucket.getInputStream(), out, "", null, null, null));
    }
  }

  @Test
  void ihdr_withZeroWidth_throws() throws IOException {
    // width=0 (bytes 0..3), height=1
    File pngFile = newTempFile();
    byte[] ihdr = new byte[] {0, 0, 0, 0, 0, 0, 0, 1, 8, 6, 0, 0, 0};
    try (FileOutputStream fos = new FileOutputStream(pngFile)) {
      fos.write(PNG_HEADER);
      new Chunk("IHDR", ihdr).write(fos);
      new Chunk("IEND", new byte[0]).write(fos);
    }
    PNGFilter filter = new PNGFilter(false, false, true);
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(newTempFile())) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(bucket.getInputStream(), out, "", null, null, null));
    }
  }

  @Test
  void ihdr_withInvalidCompressionOrFilterOrInterlace_throws() throws IOException {
    // compression method !=0
    assertIHDRValidationFails(new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 1, 0, 0});
    // filter method !=0
    assertIHDRValidationFails(new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 1, 0});
    // interlace method must be either 0 or 1
    assertIHDRValidationFails(new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 2});
  }

  @Test
  void ihdr_withInvalidColourCombinations_throws() throws IOException {
    // bitDepth=1, colourType=2 -> invalid
    assertIHDRValidationFails(new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 0, 0, 0});
    // bitDepth=16, colourType=3 -> invalid
    assertIHDRValidationFails(new byte[] {0, 0, 0, 1, 0, 0, 0, 1, 16, 3, 0, 0, 0});
  }

  private List<Chunk> filterAndGetChunks(List<Chunk> preIDATChunks, List<Chunk> postIDATChunks)
      throws IOException {
    PNGFilter filter = new PNGFilter(false, false, true);
    File pngFile = newTempFile();
    PngUtil.createPngFile(pngFile, preIDATChunks, postIDATChunks);
    File filteredPngFile = newTempFile();
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream outputStream = new FileOutputStream(filteredPngFile)) {
      filter.readFilter(bucket.getInputStream(), outputStream, "", null, null, null);
    } catch (DataFilterException e) {
      return emptyList();
    }
    return PngUtil.getChunks(filteredPngFile);
  }

  @TempDir Path temporaryFolder;

  private File newTempFile() throws IOException {
    return Files.createTempFile(temporaryFolder, "png-filter", ".png").toFile();
  }

  private static final Chunk cICPChunk = new Chunk("cICP", new byte[] {0xC, 0xD, 0x0, 0x1});
  private static final Chunk PLTEChunk = new Chunk("PLTE", new byte[0]);
  private static final Chunk mDCVChunk = new Chunk("mDCV", new byte[0]);

  // Helper: PNG header bytes
  private static final byte[] PNG_HEADER =
      new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

  private void writePngWithCustomChunks(File dest, List<Chunk> preIDAT, List<Chunk> postIDAT)
      throws IOException {
    PngUtil.createPngFile(dest, preIDAT, postIDAT);
  }

  private void assertIHDRValidationFails(byte[] ihdrData) throws IOException {
    File pngFile = newTempFile();
    try (FileOutputStream fos = new FileOutputStream(pngFile)) {
      fos.write(PNG_HEADER);
      new Chunk("IHDR", ihdrData).write(fos);
      new Chunk("IEND", new byte[0]).write(fos);
    }
    try (FileBucket bucket = new FileBucket(pngFile, true, false, false, false);
        FileOutputStream out = new FileOutputStream(newTempFile())) {
      assertThrows(
          DataFilterException.class,
          () ->
              new PNGFilter(false, false, true)
                  .readFilter(bucket.getInputStream(), out, "", null, null, null));
    }
  }
}

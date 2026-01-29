package org.bitpedia.collider.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubmissionTest {

  @Mock private FormatHandler formatHandler;

  @Mock private Bitcollider.Progress progress;

  @ParameterizedTest
  @CsvSource({
    "/tmp/example/file.txt,file.txt",
    "/tmp/example/.hidden,.hidden",
    "file.mp3,file.mp3"
  })
  void extractName_whenPathProvided_returnsBaseName(String input, String expected) {
    assertEquals(expected, Submission.extractName(input));
  }

  @ParameterizedTest
  @CsvSource({"song.mp3,mp3", "noext,", "archive.tar.gz,gz"})
  void extractExt_whenFilenameProvided_returnsExtension(String input, String expected) {
    String ext = Submission.extractExt(input);
    assertEquals(expected == null ? "" : expected, ext);
  }

  @Test
  void addAttribute_whenNullOrDuplicate_ignored() {
    Submission submission = new Submission(new Bitcollider(List.of()), null, true);

    submission.addAttribute("key", null);
    assertNull(submission.getAttribute("key"));

    submission.addAttribute("key", "value");
    submission.addAttribute("key", "second");
    assertEquals("value", submission.getAttribute("key"));
  }

  @Test
  void addAttribute_whenAdditionalBitprint_prefixesIndex() throws Exception {
    Submission submission = new Submission(new Bitcollider(List.of()), null, true);
    setBitprintCountToOne(submission);

    submission.addAttribute("bitprint", "abc");

    assertEquals("abc", submission.getAttribute("1.bitprint"));
    assertNull(submission.getAttribute("bitprint"));
  }

  @Test
  void analyzeFile_whenMatchingExtOnlyAndUnknownExtension_returnsFalseAndReportsSkip(
      @TempDir Path tempDir) throws Exception {
    Path sample = Files.writeString(tempDir.resolve("unknown.bin"), "data");
    Bitcollider bitcollider = new Bitcollider(List.of());
    bitcollider.setProgress(progress);
    Submission submission = new Submission(bitcollider, null, true);

    boolean result = submission.analyzeFile(sample.toString(), true);

    assertFalse(result);
    assertEquals(0, submission.getNumBitprints());
    verify(progress).progress(0, sample.toString(), "skipped.");
  }

  @Test
  void analyzeFile_inPreviewMode_incrementsBitprintsWithoutAttributes(@TempDir Path tempDir)
      throws Exception {
    Path sample = Files.writeString(tempDir.resolve("preview.txt"), "content");
    Bitcollider bitcollider = new Bitcollider(List.of());
    bitcollider.setPreview(true);
    Submission submission = new Submission(bitcollider, null, true);

    boolean result = submission.analyzeFile(sample.toString(), false);

    assertTrue(result);
    assertEquals(1, submission.getNumBitprints());
    assertNull(submission.getAttribute("bitprint"));
    assertNull(bitcollider.getError());
    assertNull(bitcollider.getWarning());
  }

  @Test
  void analyzeFile_withMemAnalyzeHandler_collectsHashesAndCustomAttributes(@TempDir Path tempDir)
      throws Exception {
    Path sample = Files.writeString(tempDir.resolve("sample.txt"), "hello world");

    when(formatHandler.supportsExtension("txt")).thenReturn(true);
    when(formatHandler.supportsMemAnalyze()).thenReturn(true);
    when(formatHandler.analyzeFinal()).thenReturn(Map.of("format.attr", "present"));

    Bitcollider bitcollider = new Bitcollider(List.of(formatHandler));
    bitcollider.setCalcMd5(true);
    bitcollider.setCalcCrc32(true);
    bitcollider.setProgress(progress);

    Submission submission = new Submission(bitcollider, null, true);

    boolean result = submission.analyzeFile(sample.toString(), false);

    assertTrue(result);
    assertEquals(1, submission.getNumBitprints());
    assertNotNull(submission.getAttribute("bitprint"));
    assertEquals(Bitcollider.getAgentString(), submission.getAttribute("head.agent"));
    assertEquals("S" + Bitcollider.BC_SUBMITSPECVER, submission.getAttribute("head.version"));
    assertEquals("present", submission.getAttribute("format.attr"));

    String expectedMd5 =
        bytesToHex(
            MessageDigest.getInstance("MD5")
                .digest("hello world".getBytes(StandardCharsets.US_ASCII)));
    assertEquals(expectedMd5, submission.getAttribute("tag.md5.md5"));

    CRC32 crc32 = new CRC32();
    crc32.update("hello world".getBytes(StandardCharsets.US_ASCII));
    String expectedCrc32 =
        String.format("%8s", Long.toHexString(crc32.getValue())).replace(' ', '0');
    assertEquals(expectedCrc32, submission.getAttribute("tag.crc32.crc32"));

    ArgumentCaptor<Integer> percentCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(progress, atLeastOnce()).progress(percentCaptor.capture(), any(), any());
    assertTrue(percentCaptor.getAllValues().contains(0));
    assertTrue(percentCaptor.getAllValues().contains(100));

    verify(formatHandler).analyzeInit();
    verify(formatHandler, atLeastOnce()).analyzeUpdate(any(byte[].class), anyInt());
    verify(formatHandler).analyzeFinal();
  }

  @Test
  @SuppressWarnings("unchecked")
  void analyzeFile_withNonStringAttributes_throwsClassCastException(@TempDir Path tempDir)
      throws Exception {
    Path sample = Files.writeString(tempDir.resolve("sample.txt"), "hello world");

    when(formatHandler.supportsExtension("txt")).thenReturn(true);
    when(formatHandler.supportsMemAnalyze()).thenReturn(true);
    @SuppressWarnings("rawtypes")
    Map rawMap = Collections.singletonMap("bad", 5);
    when(formatHandler.analyzeFinal()).thenReturn(rawMap);

    Bitcollider bitcollider = new Bitcollider(List.of(formatHandler));
    Submission submission = new Submission(bitcollider, null, true);
    String filePath = sample.toString();

    assertThrows(ClassCastException.class, () -> submission.analyzeFile(filePath, false));
  }

  @Test
  void recurseDir_withNestedFiles_countsAllFilesWhenRecurseDeepTrue(@TempDir Path tempDir)
      throws Exception {
    Path dir = Files.createDirectory(tempDir.resolve("root"));
    Files.writeString(dir.resolve("one.txt"), "1");
    Path nested = Files.createDirectory(dir.resolve("nested"));
    Files.writeString(nested.resolve("two.txt"), "2");

    Bitcollider bitcollider = new Bitcollider(List.of());
    bitcollider.setPreview(true);
    Submission submission = new Submission(bitcollider, null, true);

    int counted = submission.recurseDir(dir.toString(), true, true);

    assertEquals(2, counted);
    assertEquals(2, submission.getNumBitprints());
  }

  @Test
  void makeHtml_withoutBitprints_setsErrorAndReturnsFalse() {
    Bitcollider bitcollider = new Bitcollider(List.of());
    Submission submission = new Submission(bitcollider, null, true);
    StringWriter writer = new StringWriter();

    boolean result = submission.makeHtml(new PrintWriter(writer), null);

    assertFalse(result);
    assertEquals("The submission contained no bitprints.", bitcollider.getError());
  }

  @Test
  void makeHtml_withAttributes_escapesValuesAndHonorsAutoSubmitFlag(@TempDir Path tempDir)
      throws Exception {
    Path sample = Files.writeString(tempDir.resolve("escaped.txt"), "abc");
    Bitcollider bitcollider = new Bitcollider(List.of());
    Submission submission = new Submission(bitcollider, null, false);

    setBitprintCountToOne(submission);
    setFileName(submission, sample.getFileName().toString());
    submission.addAttribute("tag.custom", "\"<&>");

    StringWriter writer = new StringWriter();
    boolean result = submission.makeHtml(new PrintWriter(writer), "http://example.com");

    assertTrue(result);
    String html = writer.toString();
    assertTrue(html.contains("<BODY>"));
    assertFalse(html.contains("onLoad"));
    assertTrue(html.contains("Bitprint Submission " + sample.getFileName()));
    assertTrue(html.contains("&quot;&lt;&amp;&gt;"));
    assertTrue(html.contains("\"<&>"));
  }

  private static void setBitprintCountToOne(Object target) throws Exception {
    Field field = target.getClass().getDeclaredField("numBitprints");
    field.setAccessible(true);
    field.setInt(target, 1);
  }

  private static void setFileName(Object target, String value) throws Exception {
    Field field = target.getClass().getDeclaredField("fileName");
    field.setAccessible(true);
    field.set(target, value);
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}

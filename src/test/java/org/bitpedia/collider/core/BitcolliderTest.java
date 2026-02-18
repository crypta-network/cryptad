package org.bitpedia.collider.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BitcolliderTest {

  @Mock private FormatHandler formatHandler;

  @Test
  void getAgentString_returnsFormattedVersion() {
    String agent = Bitcollider.getAgentString();

    String expected =
        Bitcollider.BC_AGENTNAME
            + "/"
            + Bitcollider.BC_VERSION
            + " ("
            + Bitcollider.BC_AGENTBUILD
            + ")";
    assertEquals(expected, agent);
  }

  @Test
  void getFormatHandler_whenExtensionSupported_returnsHandler() {
    when(formatHandler.supportsExtension("txt")).thenReturn(true);
    Bitcollider bitcollider = new Bitcollider(Collections.singletonList(formatHandler));

    FormatHandler found = bitcollider.getFormatHandler("txt");

    assertSame(formatHandler, found);
    verify(formatHandler).supportsExtension("txt");
  }

  @Test
  void getFormatHandler_whenNoHandlerMatches_returnsNull() {
    when(formatHandler.supportsExtension("mp3")).thenReturn(false);
    Bitcollider bitcollider = new Bitcollider(Collections.singletonList(formatHandler));

    FormatHandler found = bitcollider.getFormatHandler("mp3");

    assertNull(found);
    verify(formatHandler).supportsExtension("mp3");
  }

  @Test
  void generateSubmission_withExistingFile_collectsAttributes(@TempDir Path tempDir)
      throws IOException {
    Path sample = tempDir.resolve("sample.txt");
    Files.writeString(sample, "hello world");

    when(formatHandler.supportsExtension("txt")).thenReturn(true);
    when(formatHandler.supportsMemAnalyze()).thenReturn(false);
    when(formatHandler.supportsFileAnalyze()).thenReturn(true);
    when(formatHandler.analyzeFile(sample.toString()))
        .thenReturn(Map.of("custom.attribute", "custom"));

    Bitcollider bitcollider = new Bitcollider(List.of(formatHandler));

    Submission submission =
        bitcollider.generateSubmission(Collections.singletonList(sample.toString()), "txt", false);

    assertNotNull(submission);
    assertFalse(submission.isAutoSubmit());
    assertEquals(Bitcollider.getAgentString(), submission.getAttribute("head.agent"));
    assertEquals("S" + Bitcollider.BC_SUBMITSPECVER, submission.getAttribute("head.version"));
    assertEquals("custom", submission.getAttribute("custom.attribute"));
    assertEquals(sample.getFileName().toString(), submission.getAttribute("tag.filename.filename"));
    verify(formatHandler, atLeastOnce()).supportsExtension("txt");
    verify(formatHandler).analyzeFile(sample.toString());
  }

  @Test
  void setters_whenUpdated_reflectNewValues() {
    Bitcollider bitcollider = new Bitcollider(Collections.emptyList());

    bitcollider.setCalcCrc32(true);
    bitcollider.setCalcMd5(true);
    bitcollider.setPreview(true);
    bitcollider.setExitNow(true);
    bitcollider.setError("err");
    bitcollider.setWarning("warn");

    assertTrue(bitcollider.isCalcCrc32());
    assertTrue(bitcollider.isCalcMd5());
    assertTrue(bitcollider.isPreview());
    assertTrue(bitcollider.isExitNow());
    assertEquals("err", bitcollider.getError());
    assertEquals("warn", bitcollider.getWarning());
  }
}

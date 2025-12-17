package network.crypta.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class MergeSFSTest {

  @ParameterizedTest
  @MethodSource("mergeCases")
  void merge_whenVariousInputs_expectMergedInDeterministicOrder(
      String sourceSfs, String overrideSfs, String expectedMergedSfs) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    MergeSFS.merge(
        new ByteArrayInputStream(sourceSfs.getBytes(StandardCharsets.UTF_8)),
        new ByteArrayInputStream(overrideSfs.getBytes(StandardCharsets.UTF_8)),
        out);

    assertEquals(expectedMergedSfs, out.toString(StandardCharsets.UTF_8));
  }

  private static Stream<Arguments> mergeCases() {
    return Stream.of(
        Arguments.of("b=2\nEnd\n", "a=1\nEnd\n", "a=1\nb=2\nEnd\n"),
        Arguments.of("a=1\nEnd\n", "a=2\nEnd\n", "a=2\nEnd\n"),
        Arguments.of(
            "greeting=こんにちは\nEnd\n", "emoji=🙂\nEnd\n", "emoji=🙂\ngreeting=こんにちは\nEnd\n"));
  }

  @Test
  void mergeInPlace_whenOverrideNull_expectNoChange() throws IOException {
    SimpleFieldSet source = new SimpleFieldSet("a=1\nEnd\n", false, true, false);
    MergeSFS.mergeInPlace(source, null);
    assertEquals("a=1\nEnd\n", source.toOrderedString());
  }

  @Test
  void main_whenMergingInPlace_expectSourceNotTruncatedBeforeMerge(@TempDir Path tempDir)
      throws IOException {
    Path sourceFile = tempDir.resolve("source.sfs");
    Path overrideFile = tempDir.resolve("override.sfs");

    Files.writeString(sourceFile, "b=2\nEnd\n", StandardCharsets.UTF_8);
    Files.writeString(overrideFile, "a=1\nEnd\n", StandardCharsets.UTF_8);

    MergeSFS.main(new String[] {sourceFile.toString(), overrideFile.toString()});

    assertEquals("a=1\nb=2\nEnd\n", Files.readString(sourceFile, StandardCharsets.UTF_8));
  }
}

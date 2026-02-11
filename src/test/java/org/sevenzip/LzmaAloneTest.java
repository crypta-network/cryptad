package org.sevenzip;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class LzmaAloneTest {
  private PrintStream originalOut;
  private PrintStream originalLogStream;
  private ByteArrayOutputStream capturedOut;

  @BeforeEach
  void setUp() {
    originalOut = System.out;
    originalLogStream = LzmaAlone.getLogStream();
    capturedOut = new ByteArrayOutputStream();
    LzmaAlone.setLogStream(new PrintStream(capturedOut, false, StandardCharsets.UTF_8));
  }

  @AfterEach
  void tearDown() {
    LzmaAlone.setLogStream(originalLogStream);
    System.setOut(originalOut);
  }

  @Test
  void parse_whenEncodeArgsProvided_setsCommandAndFiles() {
    LzmaAlone.CommandLine cmd = new LzmaAlone.CommandLine();

    boolean parsed = cmd.parse(new String[] {"e", "input.file", "output.file"});

    assertTrue(parsed);
    assertEquals(LzmaAlone.CommandLine.K_ENCODE, getIntField(cmd, "command"));
    assertEquals("input.file", getStringField(cmd, "inFile"));
    assertEquals("output.file", getStringField(cmd, "outFile"));
  }

  @Test
  void parse_whenSwitchesProvided_updatesAllParameters() {
    LzmaAlone.CommandLine cmd = new LzmaAlone.CommandLine();

    boolean parsed =
        cmd.parse(
            new String[] {
              "-d20", "-fb64", "-lc4", "-lp1", "-pb3", "-mfbt2", "-eos", "e", "input", "output"
            });

    assertTrue(parsed);
    assertTrue(getBooleanField(cmd, "dictionarySizeIsDefined"));
    assertEquals(1 << 20, getIntField(cmd, "dictionarySize"));
    assertEquals(64, getIntField(cmd, "fb"));
    assertEquals(4, getIntField(cmd, "lc"));
    assertEquals(1, getIntField(cmd, "lp"));
    assertEquals(3, getIntField(cmd, "pb"));
    assertEquals(0, getIntField(cmd, "matchFinder"));
    assertTrue(getBooleanField(cmd, "eos"));
    assertEquals(LzmaAlone.CommandLine.K_ENCODE, getIntField(cmd, "command"));
  }

  @Test
  void parseSwitch_whenMatchFinderUnknown_returnsFalse() {
    LzmaAlone.CommandLine cmd = new LzmaAlone.CommandLine();

    boolean parsed = cmd.parseSwitch("mfunknown");

    assertFalse(parsed);
    assertEquals(1, getIntField(cmd, "matchFinder")); // default remains unchanged
  }

  @Test
  void parse_whenBenchmarkPassesInvalid_returnsFalse() {
    LzmaAlone.CommandLine cmd = new LzmaAlone.CommandLine();

    boolean parsed = cmd.parse(new String[] {"b", "0"});

    assertFalse(parsed);
  }

  @Test
  void main_whenArgsMissing_printsHelp() throws Exception {
    System.setOut(new PrintStream(capturedOut, false, StandardCharsets.UTF_8));

    LzmaAlone.main(new String[] {});

    String output = capturedOut.toString(StandardCharsets.UTF_8);
    assertTrue(output.contains("Usage:  LZMA <e|d> [<switches>...] inputFile outputFile"));
  }

  @Test
  void main_whenDecodeWithTooShortInput_throws() throws Exception {
    System.setOut(new PrintStream(capturedOut, false, StandardCharsets.UTF_8));
    Path tempFile = Files.createTempFile("lzma-empty", ".lzma");
    Path outFile = Files.createTempFile("lzma-empty-out", ".bin");
    String[] decodeArgs = new String[] {"d", tempFile.toString(), outFile.toString()};

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> LzmaAlone.main(decodeArgs));

    assertTrue(ex.getMessage().contains("input .lzma file is too short"));
  }

  @Test
  void main_whenEncodeAndDecodeRoundTrip_preservesContent(@TempDir Path tempDir) throws Exception {
    Path source = tempDir.resolve("source.txt");
    Path encoded = tempDir.resolve("encoded.lzma");
    Path decoded = tempDir.resolve("decoded.txt");
    Files.writeString(source, "Crypta LZMA test payload", StandardCharsets.UTF_8);

    System.setOut(new PrintStream(capturedOut, false, StandardCharsets.UTF_8));
    LzmaAlone.main(new String[] {"e", source.toString(), encoded.toString()});
    LzmaAlone.main(new String[] {"d", encoded.toString(), decoded.toString()});

    byte[] original = Files.readAllBytes(source);
    byte[] roundTripped = Files.readAllBytes(decoded);
    assertEquals(
        new String(original, StandardCharsets.UTF_8),
        new String(roundTripped, StandardCharsets.UTF_8));
    assertTrue(Files.size(encoded) > 0);
  }

  private static int getIntField(LzmaAlone.CommandLine cmd, String fieldName) {
    return (int) readField(cmd, fieldName);
  }

  private static boolean getBooleanField(LzmaAlone.CommandLine cmd, String fieldName) {
    return (boolean) readField(cmd, fieldName);
  }

  private static String getStringField(LzmaAlone.CommandLine cmd, String fieldName) {
    return (String) readField(cmd, fieldName);
  }

  private static Object readField(LzmaAlone.CommandLine cmd, String fieldName) {
    try {
      Field field = LzmaAlone.CommandLine.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(cmd);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException("Unable to read field " + fieldName, e);
    }
  }
}

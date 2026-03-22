package network.crypta.support.io;

import java.nio.charset.Charset;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FilenameSanitizerTest {

  @ParameterizedTest(name = "{0} on {1}")
  @MethodSource("sanitizeCases")
  void sanitizeFileName_matchesFileUtil(
      String input, FileUtil.OperatingSystem os, String extraChars) {
    Charset charset = FileUtil.getFileEncodingCharset();
    boolean windowsLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isWindows;
    boolean macLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isMac;
    boolean unixLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isUnix;

    String actual =
        FilenameSanitizer.sanitizeFileName(
            input, charset, windowsLike, macLike, unixLike, extraChars);

    assertEquals(FileUtil.sanitizeFileName(input, os, extraChars), actual);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("sanitizeParityCases")
  void sanitizeFileName_matchesFileUtilSanitize(String input) {
    Charset charset = FileUtil.getFileEncodingCharset();
    FileUtil.OperatingSystem os = FileUtil.detectedOS;
    boolean windowsLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isWindows;
    boolean macLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isMac;
    boolean unixLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isUnix;

    String actual =
        FilenameSanitizer.sanitizeFileName(input, charset, windowsLike, macLike, unixLike, "");

    assertEquals(FileUtil.sanitize(input), actual);
  }

  @ParameterizedTest(name = "{0} on {1}")
  @MethodSource("exceptionCases")
  void sanitizeFileName_matchesFileUtilForUnsupportedReplacement(
      String input, FileUtil.OperatingSystem os, String extraChars) {
    Charset charset = FileUtil.getFileEncodingCharset();
    boolean windowsLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isWindows;
    boolean macLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isMac;
    boolean unixLike = os == FileUtil.OperatingSystem.UNKNOWN || os.isUnix;

    assertThrows(
        IllegalArgumentException.class,
        () ->
            FilenameSanitizer.sanitizeFileName(
                input, charset, windowsLike, macLike, unixLike, extraChars));
    assertThrows(
        IllegalArgumentException.class, () -> FileUtil.sanitizeFileName(input, os, extraChars));
  }

  private static Stream<Arguments> sanitizeCases() {
    return Stream.of(
        Arguments.of("con.txt", FileUtil.OperatingSystem.WINDOWS, ""),
        Arguments.of("file. ", FileUtil.OperatingSystem.WINDOWS, ""),
        Arguments.of("a/b", FileUtil.OperatingSystem.LINUX, ""),
        Arguments.of("a/b", FileUtil.OperatingSystem.GENERIC_UNIX, ""),
        Arguments.of("a/b.", FileUtil.OperatingSystem.UNKNOWN, ""));
  }

  private static Stream<Arguments> sanitizeParityCases() {
    return Stream.of(
        Arguments.of("plain-name.txt"),
        Arguments.of("a/b"),
        Arguments.of("  leading and trailing  "),
        Arguments.of("name?.txt"));
  }

  private static Stream<Arguments> exceptionCases() {
    return Stream.of(Arguments.of("name", FileUtil.OperatingSystem.WINDOWS, " -_"));
  }
}

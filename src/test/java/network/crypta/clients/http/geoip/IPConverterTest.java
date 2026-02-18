package network.crypta.clients.http.geoip;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class IPConverterTest {

  @TempDir Path tempDir;

  @Test
  void getInstance_whenCalledTwiceWithSameFile_expectSameSingletonInstance() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    Files.writeString(dbFile, START_MARKER, StandardCharsets.ISO_8859_1);

    // Act
    IPConverter first = IPConverter.getInstance(dbFile.toFile());
    IPConverter second = IPConverter.getInstance(dbFile.toFile());

    // Assert
    assertSame(first, second);
  }

  @Test
  void getInstance_whenCalledWithDifferentFiles_expectRecreatedInstance() throws IOException {
    // Arrange
    Path firstDb = tempDir.resolve("geoip-1.dat");
    Path secondDb = tempDir.resolve("geoip-2.dat");
    Files.writeString(firstDb, START_MARKER, StandardCharsets.ISO_8859_1);
    Files.writeString(secondDb, START_MARKER, StandardCharsets.ISO_8859_1);

    // Act
    IPConverter first = IPConverter.getInstance(firstDb.toFile());
    IPConverter second = IPConverter.getInstance(secondDb.toFile());

    // Assert
    assertNotSame(first, second);
  }

  @Test
  void ip2num_whenValidIPv4_expectConvertedLong() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    long result = converter.ip2num(ipv4(1, 2, 3, 4));

    // Assert
    assertEquals(0x01020304L, result);
  }

  @ParameterizedTest
  @MethodSource("invalidIpv4Inputs")
  void ip2num_whenNotValidIPv4_expectThrowsNumberFormatException(String ip) {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act / Assert
    assertThrows(NumberFormatException.class, () -> converter.ip2num(ip));
  }

  @Test
  void ip2num_whenOctetsExceedByte_expectAppliesModulo256() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    long wrapped = converter.ip2num(ipv4(257, 0, 0, 0));
    long zeroed = converter.ip2num(ipv4(256, 0, 0, 0));

    // Assert
    assertEquals(1L << 24, wrapped);
    assertEquals(0L, zeroed);
  }

  @Test
  void locateIP_whenIpIsNull_expectNull() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    IPConverter.Country result = converter.locateIP((String) null);

    // Assert
    assertNull(result);
  }

  @ParameterizedTest
  @MethodSource("invalidLocateIpInputs")
  void locateIP_whenIpIsNotIPv4_expectNull(String ip) {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    IPConverter.Country result = converter.locateIP(ip);

    // Assert
    assertNull(result);
  }

  @Test
  void locateIP_whenDbFileDoesNotExist_expectNull() {
    // Arrange
    Path missingDbFile = tempDir.resolve(MISSING_DB_FILE_NAME);
    IPConverter converter = IPConverter.getInstance(missingDbFile.toFile());

    // Act
    IPConverter.Country result = converter.locateIP(ipv4WithLastOctet(150));

    // Assert
    assertNull(result);
  }

  @Test
  void locateIP_whenDbIsValid_expectCountryForIPv4String() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(
        dbFile,
        List.of(
            new DbEntry("US", 2), // 2..8
            new DbEntry("DE", 1), // 1
            new DbEntry("FR", 0) // 0
            ));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    // Act
    IPConverter.Country us = converter.locateIP(ipv4WithLastOctet(3));
    IPConverter.Country de = converter.locateIP(ipv4WithLastOctet(1));
    IPConverter.Country fr = converter.locateIP(ipv4WithLastOctet(0));

    // Assert
    assertEquals(IPConverter.Country.US, us);
    assertEquals(IPConverter.Country.DE, de);
    assertEquals(IPConverter.Country.FR, fr);
  }

  @Test
  void locateIP_whenDbIsValid_expectCountryForIPv4Bytes() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(
        dbFile,
        List.of(
            new DbEntry("US", 2), // 2..8
            new DbEntry("DE", 1), // 1
            new DbEntry("FR", 0) // 0
            ));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    // Act
    IPConverter.Country result = converter.locateIP(new byte[] {0, 0, 0, (byte) 1});

    // Assert
    assertEquals(IPConverter.Country.DE, result);
  }

  @Test
  void locateIP_whenDbHasUnknownCountryCode_expectNullForThatRange() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(
        dbFile,
        List.of(
            new DbEntry("QQ", 2), // unknown country => stored as -1 => null results
            new DbEntry("DE", 1),
            new DbEntry("FR", 0)));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    // Act
    IPConverter.Country unknown = converter.locateIP(ipv4WithLastOctet(3));
    IPConverter.Country known = converter.locateIP(ipv4WithLastOctet(1));

    // Assert
    assertNull(unknown);
    assertEquals(IPConverter.Country.DE, known);
  }

  @Test
  void locateIP_whenDbCorrupt_expectNullAndNoRetryUntilRestart() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    // Corrupt: invalid base85 chars (spaces) will trip decodeBase85 => dbFileCorrupt=true.
    Files.writeString(dbFile, START_MARKER + "US     ", StandardCharsets.ISO_8859_1);
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    // Act
    IPConverter.Country firstAttempt = converter.locateIP(ipv4WithLastOctet(1));
    writeDbFile(dbFile, List.of(new DbEntry("US", 0), new DbEntry("US", 0), new DbEntry("US", 0)));
    IPConverter.Country secondAttemptAfterFix = converter.locateIP(ipv4WithLastOctet(1));

    // Assert
    assertNull(firstAttempt);
    assertNull(secondAttemptAfterFix);
  }

  @Test
  void locateIP_whenByteArrayIsNull_expectNull() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    IPConverter.Country result = converter.locateIP((byte[]) null);

    // Assert
    assertNull(result);
  }

  @Test
  void locateIP_whenByteArrayLengthIsUnsupported_expectNull() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();

    // Act
    IPConverter.Country result = converter.locateIP(new byte[] {1, 2, 3});

    // Assert
    assertNull(result);
  }

  @Test
  void locateIP_whenIpv6Is6to4_expectConvertedAndLocated() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(dbFile, List.of(new DbEntry("US", 2), new DbEntry("DE", 1), new DbEntry("FR", 0)));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    byte[] ipv6 =
        new byte[] {
          0x20, 0x02, // 2002::/16 prefix
          0, 0, 0, (byte) 1, // embedded IPv4 bytes
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

    // Act
    IPConverter.Country result = converter.locateIP(ipv6);

    // Assert
    assertEquals(IPConverter.Country.DE, result);
  }

  @Test
  void locateIP_whenIpv6IsIpv4Compatible_expectConvertedAndLocated() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(dbFile, List.of(new DbEntry("US", 2), new DbEntry("DE", 1), new DbEntry("FR", 0)));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    byte[] ipv6 = new byte[16];
    ipv6[12] = 0;
    ipv6[13] = 0;
    ipv6[14] = 0;
    ipv6[15] = (byte) 1;

    // Act
    IPConverter.Country result = converter.locateIP(ipv6);

    // Assert
    assertEquals(IPConverter.Country.DE, result);
  }

  @Test
  void locateIP_whenIpv6IsTeredo_expectDeinvertedAndLocated() throws IOException {
    // Arrange
    Path dbFile = tempDir.resolve(DB_FILE_NAME);
    writeDbFile(dbFile, List.of(new DbEntry("US", 2), new DbEntry("DE", 1), new DbEntry("FR", 0)));
    IPConverter converter = IPConverter.getInstance(dbFile.toFile());

    byte[] ipv6 = new byte[16];
    ipv6[0] = 0x20;
    ipv6[1] = 0x01;
    ipv6[2] = 0x00;
    ipv6[3] = 0x00;
    // 12..15: client address (inverted)
    ipv6[12] = (byte) 0xff;
    ipv6[13] = (byte) 0xff;
    ipv6[14] = (byte) 0xff;
    ipv6[15] = (byte) (1 ^ 0xff);

    // Act
    IPConverter.Country result = converter.locateIP(ipv6);

    // Assert
    assertEquals(IPConverter.Country.DE, result);
  }

  @Test
  void locateIP_whenIpv6IsNotConvertible_expectNull() {
    // Arrange
    IPConverter converter = newConverterWithMissingDb();
    byte[] ipv6 = new byte[16];
    ipv6[0] = 0x20;
    ipv6[1] = 0x01;
    ipv6[2] = 0x0d;
    ipv6[3] = (byte) 0xb8; // 2001:db8::/32, documentation prefix

    // Act
    IPConverter.Country result = converter.locateIP(ipv6);

    // Assert
    assertNull(result);
  }

  @Test
  void country_hasFlagIcon_whenResourceExists_expectTrue() {
    // Arrange / Act
    boolean hasFlag = IPConverter.Country.US.hasFlagIcon();

    // Assert
    assertTrue(hasFlag);
  }

  @Test
  void country_getFlagIconPath_whenResourceExists_expectRelativePath() {
    // Arrange / Act
    String path = IPConverter.Country.US.getFlagIconPath();

    // Assert
    assertEquals("icon/flags/us.png", path);
  }

  @Test
  void country_getFlagIconPath_whenResourceMissing_expectNull() {
    // Arrange / Act
    String path = IPConverter.Country.ZZ.getFlagIconPath();

    // Assert
    assertNull(path);
  }

  @Test
  void country_renderFlagIcon_whenResourceExists_expectImgChildWithExpectedAttributes() {
    // Arrange
    HTMLNode parent = new HTMLNode("div");

    // Act
    IPConverter.Country.US.renderFlagIcon(parent);

    // Assert
    assertEquals(1, parent.getChildren().size());
    HTMLNode img = parent.getChildren().getFirst();
    assertEquals("img", img.getName());
    assertEquals("flag", img.getAttribute("class"));
    assertEquals(IPConverter.Country.US.getName(), img.getAttribute("title"));
    assertNotNull(img.getAttribute("src"));
    assertTrue(img.getAttribute("src").endsWith("/icon/flags/us.png"));
  }

  @Test
  void country_renderFlagIcon_whenResourceMissing_expectNoChildAdded() {
    // Arrange
    HTMLNode parent = new HTMLNode("div");

    // Act
    IPConverter.Country.ZZ.renderFlagIcon(parent);

    // Assert
    assertTrue(parent.getChildren().isEmpty());
  }

  private IPConverter newConverterWithMissingDb() {
    Path missingDbFile = tempDir.resolve(MISSING_DB_FILE_NAME);
    return IPConverter.getInstance(missingDbFile.toFile());
  }

  private static void writeDbFile(Path dbFile, List<DbEntry> entries) throws IOException {
    List<DbEntry> stableEntries = new ArrayList<>(entries.size() + 1);
    // IPConverter's binary search never selects index 0, so real databases include an unused
    // "top" entry. Add a deterministic sentinel so small synthetic tables behave like production.
    stableEntries.add(new DbEntry("ZZ", 9));
    stableEntries.addAll(entries);
    stableEntries.sort((a, b) -> Long.compare(b.ipValue(), a.ipValue()));

    StringBuilder data = new StringBuilder(START_MARKER);
    for (DbEntry entry : stableEntries) {
      if (entry.countryCode().length() != 2) {
        throw new IllegalArgumentException(
            "countryCode must be exactly 2 chars: " + entry.countryCode());
      }
      data.append(entry.countryCode());
      data.append(encodeBase85SmallValue(entry.ipValue()));
    }
    Files.writeString(dbFile, data.toString(), StandardCharsets.ISO_8859_1);
  }

  private static String encodeBase85SmallValue(long value) {
    if (value < 0 || value > 9) {
      throw new IllegalArgumentException(
          "Test DB only supports base85 encoding for values 0..9: " + value);
    }
    // For any base >= 10 (true for IPConverter's alphabet), values 0..9 encode as a single digit.
    // decodeBase85() interprets "0000X" as X.
    return "0000" + (char) ('0' + (int) value);
  }

  private record DbEntry(String countryCode, long ipValue) {}

  private static final String DB_FILE_NAME = "geoip.dat";
  private static final String MISSING_DB_FILE_NAME = "missing-geoip.dat";
  private static final String START_MARKER = "##start##";

  private static String ipv4(int octet0, int octet1, int octet2, int octet3) {
    return octet0 + "." + octet1 + "." + octet2 + "." + octet3;
  }

  private static String ipv4WithLastOctet(int lastOctet) {
    return "0.0.0." + lastOctet;
  }

  private static List<String> invalidIpv4Inputs() {
    return List.of("", "1.2.3", String.join(".", "1", "2", "3", "4", "5"), "not-an-ip", "1..2.3");
  }

  private static List<String> invalidLocateIpInputs() {
    return List.of("not-an-ip", "1.2.3", String.join(".", "1", "2", "3", "4", "5"));
  }
}

package network.crypta.client.async;

import static network.crypta.client.async.USKDateHint.Type.DAY;
import static network.crypta.client.async.USKDateHint.Type.MONTH;
import static network.crypta.client.async.USKDateHint.Type.WEEK;
import static network.crypta.client.async.USKDateHint.Type.YEAR;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.time.temporal.TemporalField;
import java.time.temporal.WeekFields;
import java.util.Locale;
import java.util.stream.Stream;
import network.crypta.client.async.USKDateHint.Type;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.InsertableUSK;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class USKDateHintTest {

  // ---- Existing behavior checks (kept) ----

  @Test
  void get_whenYear_expectYearString() {
    // Arrange
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    // Act
    String value = hint.get(YEAR);
    // Assert
    assertEquals("2023", value);
  }

  @Test
  void get_whenMonth_expectZeroIndexedMonthString() {
    // Arrange
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    // Act
    String value = hint.get(MONTH);
    // Assert
    assertEquals("2023-5", value);
  }

  @Test
  void get_whenDay_expectFullDateString() {
    // Arrange
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    // Act
    String value = hint.get(DAY);
    // Assert
    assertEquals("2023-5-1", value);
  }

  @Test
  void get_whenWeek_expectWeekBasedYearAndWeekOfYear() {
    // Arrange
    USKDateHint hintStartOfYear = new USKDateHint(LocalDate.parse("2023-01-01"));
    USKDateHint hintEndOfYear = new USKDateHint(LocalDate.parse("2023-12-31"));
    // Act & Assert
    assertEquals("2023-WEEK-1", hintStartOfYear.get(WEEK));
    assertEquals("2024-WEEK-1", hintEndOfYear.get(WEEK));
  }

  @Test
  void getData_whenEditionProvided_expectFormattedPayload() {
    // Arrange
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    // Act
    String data = hint.getData(12345);
    // Assert
    assertEquals("HINT\n12345\n2023-5-1\n", data);
  }

  // ---- New tests ----

  @Test
  void get_whenNullType_expectDayPrecisionString() {
    // Arrange
    LocalDate date = LocalDate.of(2025, 1, 2); // Jan to also verify zero-based month handling
    USKDateHint hint = new USKDateHint(date);
    // Act
    String value = hint.get(null);
    // Assert (null behaves like requesting the most precise non-week form, i.e., day)
    assertEquals(
        "%d-%d-%d".formatted(date.getYear(), date.getMonthValue() - 1, date.getDayOfMonth()),
        value);
  }

  @Test
  void get_whenJanuary_expectZeroIndexedMonthZero() {
    // Arrange
    LocalDate date = LocalDate.of(2024, 1, 15);
    USKDateHint hint = new USKDateHint(date);
    // Act
    String month = hint.get(MONTH);
    String day = hint.get(DAY);
    // Assert
    assertEquals("2024-0", month);
    assertEquals("2024-0-15", day);
  }

  @Test
  void get_whenWeek_usesUSLocaleWeekFields() {
    // Arrange
    LocalDate date = LocalDate.of(2024, 12, 29); // A Sunday near year boundary (US weeks start Sun)
    USKDateHint hint = new USKDateHint(date);
    TemporalField weekOfYear = WeekFields.of(Locale.US).weekOfWeekBasedYear();
    TemporalField weekYear = WeekFields.of(Locale.US).weekBasedYear();
    String expected = "%d-WEEK-%d".formatted(date.get(weekYear), date.get(weekOfYear));
    // Act
    String actual = hint.get(WEEK);
    // Assert
    assertEquals(expected, actual);
  }

  @ParameterizedTest
  @MethodSource("alwaysMorePreciseThanCases")
  void alwaysMorePreciseThan_variousPairs_expectDefinedOrdering(boolean expected, Type a, Type b) {
    // Arrange
    // Act
    boolean result = a.alwaysMorePreciseThan(b);
    // Assert
    assertEquals(expected, result, () -> "%s > %s".formatted(a, b));
  }

  static Stream<Arguments> alwaysMorePreciseThanCases() {
    return Stream.of(
        // Same type never strictly more precise
        Arguments.of(false, YEAR, YEAR),
        Arguments.of(false, MONTH, MONTH),
        Arguments.of(false, DAY, DAY),
        Arguments.of(false, WEEK, WEEK),
        // Day beats everything else
        Arguments.of(true, DAY, YEAR),
        Arguments.of(true, DAY, MONTH),
        Arguments.of(true, DAY, WEEK),
        // Month and week only beat year
        Arguments.of(true, MONTH, YEAR),
        Arguments.of(false, MONTH, WEEK),
        Arguments.of(false, WEEK, MONTH),
        Arguments.of(true, WEEK, YEAR),
        // Year beats nothing
        Arguments.of(false, YEAR, MONTH),
        Arguments.of(false, YEAR, WEEK),
        Arguments.of(false, YEAR, DAY));
  }

  @Test
  void getRequestURIs_whenValidUSK_expectFourSSKsWithExpectedDocNamesInOrder() {
    // Arrange (construct a minimal, valid USK)
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    USK usk = new TestUSK(pubKeyHash, cryptoKey, "mysite", 0L, Key.ALGO_AES_PCFB_256_SHA256);

    LocalDate date = LocalDate.of(2023, 7, 15);
    USKDateHint hint = new USKDateHint(date);

    String[] expectedDocNames =
        new String[] {
          // YEAR, MONTH, DAY, WEEK (Type.values() order)
          "mysite-DATEHINT-" + hint.get(YEAR),
          "mysite-DATEHINT-" + hint.get(MONTH),
          "mysite-DATEHINT-" + hint.get(DAY),
          "mysite-DATEHINT-" + hint.get(WEEK)
        };

    // Act
    ClientSSK[] uris = hint.getRequestURIs(usk);

    // Assert
    assertEquals(4, uris.length);
    String[] actualDocNames =
        new String[] {uris[0].docName, uris[1].docName, uris[2].docName, uris[3].docName};
    assertArrayEquals(expectedDocNames, actualDocNames);
  }

  @Test
  void getInsertURIs_whenInsertableUSKProvided_expectFourURIsWithCorrectSuffixesAndOrder() {
    // Arrange: mock InsertableUSK.getInsertableSSK(String) to return an InsertableClientSSK whose
    // getInsertURI() doc name equals the provided argument. siteName is field-accessed in
    // USKDateHint; a mock yields null, so we assert on the suffix which is the interesting part.
    var insertable = Mockito.mock(InsertableUSK.class);
    Mockito.when(insertable.getInsertableSSK(Mockito.anyString()))
        .thenAnswer(
            inv -> {
              String docName = inv.getArgument(0, String.class);
              InsertableClientSSK ssk = Mockito.mock(InsertableClientSSK.class);
              Mockito.when(ssk.getInsertURI()).thenReturn(new FreenetURI("SSK", docName));
              return ssk;
            });

    LocalDate date = LocalDate.of(2023, 7, 15);
    USKDateHint hint = new USKDateHint(date);

    // Act
    FreenetURI[] uris = hint.getInsertURIs(insertable);

    // Assert
    assertEquals(4, uris.length);
    String[] suffixes =
        new String[] {hint.get(YEAR), hint.get(MONTH), hint.get(DAY), hint.get(WEEK)};
    for (int i = 0; i < uris.length; i++) {
      String dn = uris[i].getDocName();
      assertTrue(dn.endsWith("-DATEHINT-" + suffixes[i]), "docName=" + dn);
    }
  }

  /** Minimal subclass to access the protected USK constructor for tests. */
  private static final class TestUSK extends USK {
    TestUSK(
        byte[] pubKeyHash, byte[] cryptoKey, String siteName, long suggestedEdition, byte algo) {
      super(pubKeyHash, cryptoKey, siteName, suggestedEdition, algo);
    }
  }
}

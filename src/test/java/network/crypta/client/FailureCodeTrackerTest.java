package network.crypta.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.CountedOutputStream;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FailureCodeTrackerTest {

  private FailureCodeTracker fetchTracker; // insert == false
  private FailureCodeTracker insertTracker; // insert == true

  @BeforeEach
  void setup() {
    fetchTracker = new FailureCodeTracker(false);
    insertTracker = new FailureCodeTracker(true);
  }

  /** Test that the fixed size representation really is a fixed size */
  @Test
  void testSize() throws IOException {
    testSize(false);
    testSize(true);
  }

  void testSize(boolean insert) throws IOException {
    FailureCodeTracker f = new FailureCodeTracker(insert);
    int fixedLength = FailureCodeTracker.getFixedLength(insert);
    assertEquals(fixedLength, getStoredLength(f));
    f.inc(1);
    assertEquals(fixedLength, getStoredLength(f));
    f.inc(2, 2);
    assertEquals(fixedLength, getStoredLength(f));
  }

  private int getStoredLength(FailureCodeTracker f) throws IOException {
    CountedOutputStream os = new CountedOutputStream(new NullOutputStream());
    try (DataOutputStream dos = new DataOutputStream(os)) {
      f.writeFixedLengthTo(dos);
    }
    return (int) os.written();
  }

  @Test
  void incFetchMode_whenInsertTracker_expectIllegalState() {
    assertThrows(IllegalStateException.class, () -> insertTracker.inc(FetchExceptionMode.TOO_BIG));
  }

  @Test
  void incInsertMode_whenFetchTracker_expectIllegalState() {
    assertThrows(IllegalStateException.class, () -> fetchTracker.inc(InsertExceptionMode.TOO_BIG));
  }

  @Test
  void incInt_whenZeroCode_allowedAndIncrementsCountAndTotal() {
    fetchTracker.inc(0);
    assertEquals(1, fetchTracker.totalCount());
    assertEquals(1, fetchTracker.getErrorCount(0));
  }

  @Test
  void incIntegerVal_firstInsert_recordsOneButTotalsVal() {
    // Current behavior: on first insert via inc(Integer, int), map value is set to 1, but total +=
    // val.
    fetchTracker.inc(7, 5);
    assertEquals(5, fetchTracker.totalCount());
    assertEquals(1, fetchTracker.getErrorCount(7));

    // On later adding, the supplied value is added to the existing one.
    fetchTracker.inc(7, 4);
    assertEquals(9, fetchTracker.totalCount());
    assertEquals(5, fetchTracker.getErrorCount(7));
  }

  @Test
  void toString_whenEmpty_hasEmptySuffix() {
    String s = fetchTracker.toString();
    assertTrue(s.endsWith(":empty"), s);
  }

  @Test
  void toString_whenOneEntry_hasOneCodeEqualsCount() {
    fetchTracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND);
    String s = fetchTracker.toString();
    assertTrue(s.contains("one:"), s);
    assertTrue(s.contains(FetchExceptionMode.ROUTE_NOT_FOUND.code + "=" + 1), s);
  }

  @Test
  void toString_whenFewEntries_listsPairsCommaSeparated() {
    fetchTracker.inc(FetchExceptionMode.DATA_NOT_FOUND);
    fetchTracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND);
    String s = fetchTracker.toString();
    assertTrue(s.contains("="), s);
    assertTrue(s.contains(","), s);
    assertTrue(s.contains(String.valueOf(FetchExceptionMode.DATA_NOT_FOUND.code)), s);
    assertTrue(s.contains(String.valueOf(FetchExceptionMode.ROUTE_NOT_FOUND.code)), s);
  }

  @Test
  void toString_whenManyEntries_printsCountOnly() {
    // Add 10 different codes
    fetchTracker.inc(FetchExceptionMode.DATA_NOT_FOUND);
    fetchTracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND);
    fetchTracker.inc(FetchExceptionMode.REJECTED_OVERLOAD);
    fetchTracker.inc(FetchExceptionMode.TRANSFER_FAILED);
    fetchTracker.inc(FetchExceptionMode.INVALID_URI);
    fetchTracker.inc(FetchExceptionMode.TOO_BIG);
    fetchTracker.inc(FetchExceptionMode.TOO_BIG_METADATA);
    fetchTracker.inc(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS);
    fetchTracker.inc(FetchExceptionMode.ARCHIVE_RESTART);
    fetchTracker.inc(FetchExceptionMode.WRONG_MIME_TYPE);
    String s = fetchTracker.toString();
    assertTrue(s.endsWith(":10") || s.contains(":10"), s);
    assertFalse(s.contains("="), s);
  }

  @Test
  void toVerboseString_fetchAndInsert_includeCountAndMessage() {
    // Fetch tracker: use a fetch code
    fetchTracker.inc(FetchExceptionMode.TOO_BIG);
    String fetchVerbose = fetchTracker.toVerboseString();
    assertTrue(
        fetchVerbose.contains("1\t" + FetchException.getMessage(FetchExceptionMode.TOO_BIG)),
        fetchVerbose);

    // Insert tracker: use an insert code
    insertTracker.inc(InsertExceptionMode.TOO_BIG);
    String insertVerbose = insertTracker.toVerboseString();
    assertTrue(
        insertVerbose.contains("1\t" + InsertException.getMessage(InsertExceptionMode.TOO_BIG)),
        insertVerbose);
  }

  @Test
  void toFieldSet_andReconstruct_roundTripsCounts_insertAndFetch() throws Exception {
    // Fetch tracker field set
    fetchTracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND);
    fetchTracker.inc(FetchExceptionMode.TOO_BIG, 3); // stored as 1 on first writing, but total += 3
    SimpleFieldSet fsFetch = fetchTracker.toFieldSet(true);
    // Verify description and count entries exist
    String descFetch = fsFetch.get(FetchExceptionMode.ROUTE_NOT_FOUND.code + ".Description");
    String cntFetch = fsFetch.get(FetchExceptionMode.ROUTE_NOT_FOUND.code + ".Count");
    assertNotNull(descFetch);
    assertNotNull(cntFetch);
    assertEquals(FetchException.getMessage(FetchExceptionMode.ROUTE_NOT_FOUND), descFetch);
    // Round-trip via fixed-length representation for reconstruction
    FailureCodeTracker reconstructedFetch = roundTripFixedLength(fetchTracker, false);
    assertEquals(
        fetchTracker.getErrorCount(FetchExceptionMode.ROUTE_NOT_FOUND),
        reconstructedFetch.getErrorCount(FetchExceptionMode.ROUTE_NOT_FOUND));

    // Insert tracker field set
    insertTracker.inc(InsertExceptionMode.TOO_BIG);
    SimpleFieldSet fsInsert = insertTracker.toFieldSet(true);
    assertEquals(
        InsertException.getMessage(InsertExceptionMode.TOO_BIG),
        fsInsert.get(InsertExceptionMode.TOO_BIG.code + ".Description"));
    FailureCodeTracker reconstructedInsert = roundTripFixedLength(insertTracker, true);
    assertEquals(
        insertTracker.getErrorCount(InsertExceptionMode.TOO_BIG),
        reconstructedInsert.getErrorCount(InsertExceptionMode.TOO_BIG));
  }

  @Test
  void getFirstCodeFetch_and_Insert_returnsModeOrThrows() {
    // Single code => deterministic
    fetchTracker.inc(FetchExceptionMode.DATA_NOT_FOUND);
    assertEquals(FetchExceptionMode.DATA_NOT_FOUND, fetchTracker.getFirstCodeFetch());

    insertTracker.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
    assertEquals(InsertExceptionMode.ROUTE_NOT_FOUND, insertTracker.getFirstCodeInsert());

    // Wrong usage throws
    assertThrows(IllegalStateException.class, () -> fetchTracker.getFirstCodeInsert());
    assertThrows(IllegalStateException.class, () -> insertTracker.getFirstCodeFetch());
  }

  @Test
  void isFatal_fetchTracker_detectsFatalAndIgnoresZeroCounts() {
    // Non-fatal only
    fetchTracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND);
    assertFalse(fetchTracker.isFatal(false));

    // Add a fatal, then reduce its count to zero to ensure it's ignored
    int fatalCode = FetchExceptionMode.TOO_BIG.code;
    fetchTracker.inc(fatalCode, 1); // first insert stores 1, total += 1
    fetchTracker.inc(fatalCode, -1); // now map value becomes 0
    assertFalse(fetchTracker.isFatal(false));

    // Add a fatal with a positive count
    fetchTracker.inc(FetchExceptionMode.TOO_BIG);
    assertTrue(fetchTracker.isFatal(false));
  }

  @Test
  void isOneCodeOnly_and_isEmpty_behaviors() {
    FailureCodeTracker t = new FailureCodeTracker(false);
    assertTrue(t.isOneCodeOnly()); // null map treated as one-code
    assertTrue(t.isEmpty());

    t.inc(FetchExceptionMode.DATA_NOT_FOUND);
    assertTrue(t.isOneCodeOnly());
    assertFalse(t.isEmpty());

    // Reduce the existing key to zero; map not empty, still not considered empty
    t.inc(FetchExceptionMode.DATA_NOT_FOUND.code, -1);
    assertTrue(t.isOneCodeOnly());
    assertFalse(t.isEmpty());
  }

  @Test
  void getErrorCount_overloads_and_stateChecks() {
    fetchTracker.inc(FetchExceptionMode.REJECTED_OVERLOAD);
    assertEquals(1, fetchTracker.getErrorCount(FetchExceptionMode.REJECTED_OVERLOAD));
    assertThrows(
        IllegalStateException.class, () -> fetchTracker.getErrorCount(InsertExceptionMode.TOO_BIG));

    insertTracker.inc(InsertExceptionMode.TOO_BIG);
    assertEquals(1, insertTracker.getErrorCount(InsertExceptionMode.TOO_BIG));
    assertThrows(
        IllegalStateException.class, () -> insertTracker.getErrorCount(FetchExceptionMode.TOO_BIG));
  }

  @Test
  void getMessage_returnsExpectedL10nKeyForType() {
    assertEquals(
        FetchException.getMessage(FetchExceptionMode.TOO_BIG),
        fetchTracker.getMessage(FetchExceptionMode.TOO_BIG.code));
    assertEquals(
        InsertException.getMessage(InsertExceptionMode.TOO_BIG),
        insertTracker.getMessage(InsertExceptionMode.TOO_BIG.code));
  }

  @Test
  void merge_fromTracker_newKey_recordsOneButTotalsVal() {
    // Source with exact counts (build via fixed-length constructor)
    FailureCodeTracker source =
        trackerFromCounts(false, Map.of(FetchExceptionMode.TOO_BIG.code, 7));
    assertEquals(7, source.getErrorCount(FetchExceptionMode.TOO_BIG.code));

    // Merge into empty destination: first-time insert stores 1; total += 7
    fetchTracker.merge(source);
    assertEquals(1, fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    assertEquals(7, fetchTracker.totalCount());
  }

  @Test
  void merge_fromTracker_existingKey_addsFullItemCount() {
    // Destination with existing count 2
    fetchTracker = trackerFromCounts(false, Map.of(FetchExceptionMode.TOO_BIG.code, 2));
    assertEquals(2, fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    assertEquals(2, fetchTracker.totalCount());

    // Source with count 3
    FailureCodeTracker source =
        trackerFromCounts(false, Map.of(FetchExceptionMode.TOO_BIG.code, 3));

    // Merge: existing key => adds full 3
    fetchTracker.merge(source);
    assertEquals(5, fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    assertEquals(5, fetchTracker.totalCount());
  }

  @Test
  void merge_withNullSource_isNoOp() {
    fetchTracker.inc(FetchExceptionMode.TOO_BIG);

    FailureCodeTracker merged = fetchTracker.merge((FailureCodeTracker) null);

    assertSame(merged, fetchTracker);
    assertEquals(1, fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    assertEquals(1, fetchTracker.totalCount());
  }

  @Test
  void merge_fetchException_mergesCodesAndIncrementsMode() {
    // Prepare error codes in the exception (count 7 for TOO_BIG)
    FailureCodeTracker codes = trackerFromCounts(false, Map.of(FetchExceptionMode.TOO_BIG.code, 7));
    FetchException ex = new FetchException(FetchExceptionMode.TOO_BIG, codes);

    fetchTracker.merge(ex);
    // Code appears twice: once via merge (stored as 1), once via inc(mode) => +1
    assertEquals(2, fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    // Total accumulates 7 (merge) + 1 (inc(mode))
    assertEquals(8, fetchTracker.totalCount());
  }

  @Test
  void copyOf_preservesInsertFlag_mergesCountsUsingCurrentSemantics() {
    // Build original with precise count via repeated inc(int)
    FailureCodeTracker original = new FailureCodeTracker(true);
    for (int i = 0; i < 4; i++) {
      original.inc(InsertExceptionMode.TOO_BIG);
    }
    FailureCodeTracker copy = FailureCodeTracker.copyOf(original);
    assertNotNull(copy);
    assertTrue(copy.insert);
    // Using current inc(Integer,int) semantics: first insert stores 1, but totals reflect 4
    assertEquals(1, copy.getErrorCount(InsertExceptionMode.TOO_BIG.code));
    assertEquals(4, copy.totalCount());
  }

  @Test
  void copyOf_withNull_returnsNull() {
    assertNull(FailureCodeTracker.copyOf(null));
  }

  @Test
  void isDataFound_onInsertTracker_usesFetchCodes() {
    // The insert tracker expects fetch-style codes in its map for this method.
    int tooBigFetchCode = FetchExceptionMode.TOO_BIG.code;
    int routeNotFoundCode = FetchExceptionMode.ROUTE_NOT_FOUND.code;
    insertTracker.inc(tooBigFetchCode); // data found
    insertTracker.inc(routeNotFoundCode); // not data found
    assertTrue(insertTracker.isDataFound());
  }

  @Test
  void writeAndReadFixedLength_roundTripsCounts() throws Exception {
    // Prepare a tracker with exact counts (use repeated inc(int) for clarity)
    fetchTracker.inc(FetchExceptionMode.ARCHIVE_FAILURE.code);
    fetchTracker.inc(FetchExceptionMode.ARCHIVE_FAILURE.code);
    fetchTracker.inc(FetchExceptionMode.TOO_BIG.code);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      fetchTracker.writeFixedLengthTo(dos);
    }
    byte[] bytes = bos.toByteArray();

    FailureCodeTracker readBack =
        new FailureCodeTracker(false, new java.io.DataInputStream(new ByteArrayInputStream(bytes)));
    assertEquals(
        fetchTracker.getErrorCount(FetchExceptionMode.ARCHIVE_FAILURE.code),
        readBack.getErrorCount(FetchExceptionMode.ARCHIVE_FAILURE.code));
    assertEquals(
        fetchTracker.getErrorCount(FetchExceptionMode.TOO_BIG.code),
        readBack.getErrorCount(FetchExceptionMode.TOO_BIG.code));
    assertEquals(fetchTracker.totalCount(), readBack.totalCount());
  }

  @Test
  void disConstructor_withBadMagic_throwsStorageFormatException() throws IOException {
    byte[] bytes = wrongHeaderBytes(0xDEADBEEF, 1, FetchException.UPPER_LIMIT_ERROR_CODE, Map.of());
    assertThrows(
        StorageFormatException.class,
        () ->
            new FailureCodeTracker(
                false, new java.io.DataInputStream(new ByteArrayInputStream(bytes))));
  }

  @Test
  void trackerFromCounts_whenInsertTrue_buildsInsertTracker() {
    FailureCodeTracker t = trackerFromCounts(true, Map.of(InsertExceptionMode.TOO_BIG.code, 2));
    assertTrue(t.insert);
    assertEquals(2, t.getErrorCount(InsertExceptionMode.TOO_BIG));
    assertEquals(2, t.totalCount());
  }

  @Test
  void disConstructor_withBadVersion_throwsStorageFormatException() throws IOException {
    byte[] bytes =
        wrongHeaderBytes(0xb605aa08, 99, FetchException.UPPER_LIMIT_ERROR_CODE, Map.of());
    StorageFormatException ex =
        assertThrows(
            StorageFormatException.class,
            () ->
                new FailureCodeTracker(
                    false, new java.io.DataInputStream(new ByteArrayInputStream(bytes))));
    assertTrue(ex.getMessage().contains("version"));
  }

  @Test
  void disConstructor_withBadUpperLimit_throwsStorageFormatException() throws IOException {
    byte[] bytes = wrongHeaderBytes(0xb605aa08, 1, 12345, Map.of());
    StorageFormatException ex =
        assertThrows(
            StorageFormatException.class,
            () ->
                new FailureCodeTracker(
                    false, new java.io.DataInputStream(new ByteArrayInputStream(bytes))));
    assertTrue(ex.getMessage().contains("upper limit"));
  }

  @Test
  void disConstructor_withNegativeCounts_throwsStorageFormatException() throws IOException {
    // Write a single negative count at index 0
    byte[] bytes =
        wrongHeaderBytes(0xb605aa08, 1, FetchException.UPPER_LIMIT_ERROR_CODE, Map.of(0, -1));
    assertThrows(
        StorageFormatException.class,
        () ->
            new FailureCodeTracker(
                false, new java.io.DataInputStream(new ByteArrayInputStream(bytes))));
  }

  private static byte[] wrongHeaderBytes(
      int magic, int version, int upperLimit, Map<Integer, Integer> counts) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(magic);
      dos.writeInt(version);
      dos.writeInt(upperLimit);
      for (int i = 0; i < upperLimit; i++) {
        int v = counts.getOrDefault(i, 0);
        dos.writeInt(v);
      }
    }
    return bos.toByteArray();
  }

  private static FailureCodeTracker trackerFromCounts(
      boolean insert, Map<Integer, Integer> counts) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try (DataOutputStream dos = new DataOutputStream(bos)) {
        dos.writeInt(0xb605aa08); // MAGIC
        dos.writeInt(1); // VERSION
        int upper = upperLimitErrorCode(insert);
        dos.writeInt(upper);
        for (int i = 0; i < upper; i++) {
          dos.writeInt(counts.getOrDefault(i, 0));
        }
      }
      return new FailureCodeTracker(
          insert, new java.io.DataInputStream(new ByteArrayInputStream(bos.toByteArray())));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static int upperLimitErrorCode(boolean insert) {
    return insert ? insertUpperLimitErrorCode() : fetchUpperLimitErrorCode();
  }

  private static int insertUpperLimitErrorCode() {
    return InsertException.UPPER_LIMIT_ERROR_CODE;
  }

  private static int fetchUpperLimitErrorCode() {
    return FetchException.UPPER_LIMIT_ERROR_CODE;
  }

  private static FailureCodeTracker roundTripFixedLength(
      FailureCodeTracker original, boolean insert) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      original.writeFixedLengthTo(dos);
    }
    return new FailureCodeTracker(
        insert, new java.io.DataInputStream(new ByteArrayInputStream(bos.toByteArray())));
  }
}

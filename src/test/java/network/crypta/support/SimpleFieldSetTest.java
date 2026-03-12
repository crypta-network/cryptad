package network.crypta.support;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import network.crypta.node.FSParseException;
import network.crypta.support.io.LineReader;
import network.crypta.support.io.Readers;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests for {@link SimpleFieldSet} using JUnit 6.
 *
 * <p>Style: AAA (Arrange–Act–Assert). Deterministic, no external I/O.
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
class SimpleFieldSetTest {

  /**
   * Tests putSingle(String,String) method trying to store a key with two paired multi_level_chars
   * (i.e. "..").
   */
  @Test
  void testSimpleFieldSetPutSingle_StringString_WithTwoPairedMultiLevelChars() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    String methodKey = "foo..bar.";
    String methodValue = "foobar";

    // Act
    methodSFS.putSingle(methodKey, methodValue);

    // Assert
    assertEquals(methodValue, methodSFS.subset("foo").subset("").subset("bar").get(""));
    assertEquals(methodValue, methodSFS.get(methodKey));
  }

  /**
   * Tests putAppend(String,String) method trying to store a key with two paired multi_level_chars
   * (i.e. "..").
   */
  @Test
  void testSimpleFieldSetPutAppend_StringString_WithTwoPairedMultiLevelChars() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    String methodKey = "foo..bar";
    String methodValue = "foobar";

    // Act
    methodSFS.putAppend(methodKey, methodValue);

    // Assert
    assertEquals(methodValue, methodSFS.get(methodKey));
  }

  /** Tests put() and get() methods using a normal Map behaviour and without MULTI_LEVEL_CHARs */
  @Test
  void testSimpleFieldSetPutAndGet_NoMultiLevel() {
    // Arrange
    String[][] methodPairsArray = {
      {"A", "a"}, {"B", "b"}, {"C", "c"}, {"D", "d"}, {"E", "e"}, {"F", "f"}
    };
    // Act & Assert
    assertTrue(checkPutAndGetPairs(methodPairsArray));
  }

  /** Tests put() and get() methods using a normal Map behaviour and with MULTI_LEVEL_CHARs */
  @Test
  void testSimpleFieldSetPutAndGet_MultiLevel() {
    // Arrange
    String[][] methodPairsArrayDoubleLevel = {
      {"A.A", "aa"}, {"A.B", "ab"}, {"A.C", "ac"}, {"A.D", "ad"}, {"A.E", "ae"}, {"A.F", "af"}
    };
    String[][] methodPairsArrayMultiLevel = {
      {"A.A.A.A", "aa"},
      {"A.B.A", "ab"},
      {"A.C.Cc", "ac"},
      {"A.D.F", "ad"},
      {"A.E.G", "ae"},
      {"A.F.J.II.UI.BOO", "af"}
    };
    // Act & Assert
    assertTrue(checkPutAndGetPairs(methodPairsArrayDoubleLevel));
    assertTrue(checkPutAndGetPairs(methodPairsArrayMultiLevel));
  }

  /**
   * Tests subset(String) method putting two levels keys and fetching it through subset() method on
   * the first level and then get() on the second
   */
  @Test
  void testSimpleFieldSetSubset_String() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    String[][] methodPairsArrayMultiLevel = {
      {"A", "A", "aa"},
      {"A", "B", "ab"},
      {"A", "C", "ac"},
      {"A", "D", "ad"},
      {"A", "E", "ae"},
      {"A", "F", "af"}
    };
    // Act
    for (String[] value : methodPairsArrayMultiLevel) {
      methodSFS.putSingle(value[0] + SimpleFieldSet.MULTI_LEVEL_CHAR + value[1], value[2]);
    }
    // Assert (getting subsets and then values)
    for (String[] strings : methodPairsArrayMultiLevel) {
      assertEquals(methodSFS.subset(strings[0]).get(strings[1]), strings[2]);
    }
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArrayMultiLevel.length));
  }

  /**
   * Tests putAllOverwrite(SimpleFieldSet) method trying to overwrite a whole SimpleFieldSet with
   * another with same keys but different values
   */
  @Test
  void testPutAllOverwrite() {
    // Arrange
    String methodAppendedString = "buu";
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    SimpleFieldSet methodNewSFS = this.sfsFromStringPairs(methodAppendedString);

    // Act
    methodSFS.putAllOverwrite(methodNewSFS);

    // Assert
    for (String[] stringPair : SAMPLE_STRING_PAIRS) {
      assertEquals(methodSFS.get(stringPair[0]), stringPair[1] + methodAppendedString);
    }
    // Arrange another target
    SimpleFieldSet nullSFS = new SimpleFieldSet(false);
    // Act
    nullSFS.putAllOverwrite(methodNewSFS);
    // Assert
    for (String[] sampleStringPair : SAMPLE_STRING_PAIRS) {
      assertEquals(nullSFS.get(sampleStringPair[0]), sampleStringPair[1] + methodAppendedString);
    }
  }

  /** Tests put(String,SimpleFieldSet) method */
  @Test
  void testPut_StringSimpleFieldSet() {
    // Arrange
    String methodKey = "prefix";
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    SimpleFieldSet child = sfsFromSampleStringPairs();

    // Act
    methodSFS.put(methodKey, child);

    // Assert
    for (String[] sampleStringPair : SAMPLE_STRING_PAIRS) {
      assertEquals(
          methodSFS.get(methodKey + SimpleFieldSet.MULTI_LEVEL_CHAR + sampleStringPair[0]),
          sampleStringPair[1]);
    }
  }

  /** Tests put(String,SimpleFieldSet) method */
  @Test
  void testTPut_StringSimpleFieldSet() {
    // Arrange
    String methodKey = "prefix";
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    SimpleFieldSet child = sfsFromSampleStringPairs();

    // Act
    methodSFS.tput(methodKey, child);

    // Assert
    for (String[] sampleStringPair : SAMPLE_STRING_PAIRS) {
      assertEquals(
          methodSFS.get(methodKey + SimpleFieldSet.MULTI_LEVEL_CHAR + sampleStringPair[0]),
          sampleStringPair[1]);
    }
  }

  /**
   * Tests put(String,SimpleFieldSet) and tput(String,SimpleFieldSet) trying to add empty data
   * structures
   */
  @Test
  void testPutAndTPut_WithEmpty() {
    // Arrange
    SimpleFieldSet methodEmptySFS = new SimpleFieldSet(true);
    SimpleFieldSet methodSampleSFS = sfsFromSampleStringPairs();

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> methodSampleSFS.put("sample", methodEmptySFS));
    // Act (tput should not throw)
    assertDoesNotThrow(() -> methodSampleSFS.tput("sample", methodSampleSFS));
  }

  /**
   * Tests put(String,boolean) and getBoolean(String,boolean) methods consistency. The default value
   * (returned if the key is not found) is set to "false" and the real value is always set to
   * "true", so we are sure if it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringBoolean() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    int length = 15;
    for (int i = 0; i < length; i++) {
      methodSFS.put(Integer.toString(i), true);
    }

    // Act & Assert
    for (int i = 0; i < length; i++) {
      assertTrue(methodSFS.getBoolean(Integer.toString(i), false));
    }
    assertTrue(checkSimpleFieldSetSize(methodSFS, length));
  }

  /**
   * Tests put(String,int) and [getInt(String),getInt(String,int)] methods consistency. The default
   * value (returned if the key is not found) is set to a not present int value, so we are sure if
   * it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringInt() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    int[][] methodPairsArray = {{1, 1}, {2, 2}, {3, 3}, {4, 4}};
    for (int[] value : methodPairsArray) {
      methodSFS.put(Integer.toString(value[0]), value[1]);
    }

    // Act & Assert
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArray.length));
    for (int[] ints : methodPairsArray) {
      try {
        assertEquals(methodSFS.getInt(Integer.toString(ints[0])), ints[1]);
        assertEquals(methodSFS.getInt(Integer.toString(ints[0]), 5), ints[1]);
      } catch (FSParseException aException) {
        fail("Not expected exception thrown : " + aException.getMessage());
      }
    }
  }

  /**
   * Tests put(String,long) and [getLong(String),getLong(String,long)] methods consistency. The
   * default value (returned if the key is not found) is set to a not present long value, so we are
   * sure if it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringLong() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    long[][] methodPairsArray = {{1, 1}, {2, 2}, {3, 3}, {4, 4}};
    for (long[] value : methodPairsArray) {
      methodSFS.put(Long.toString(value[0]), value[1]);
    }

    // Act & Assert
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArray.length));
    for (long[] longs : methodPairsArray) {
      try {
        assertEquals(methodSFS.getLong(Long.toString(longs[0])), longs[1]);
        assertEquals(methodSFS.getLong(Long.toString(longs[0]), 5), longs[1]);
      } catch (FSParseException aException) {
        fail("Not expected exception thrown : " + aException.getMessage());
      }
    }
  }

  /**
   * Tests put(String,char) and [getChar(String),getChar(String,char)] methods consistency. The
   * default value (returned if the key is not found) is set to a not present char value, so we are
   * sure if it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringChar() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    char[][] methodPairsArray = {{'1', '1'}, {'2', '2'}, {'3', '3'}, {'4', '4'}};
    for (char[] value : methodPairsArray) {
      methodSFS.put(String.valueOf(value[0]), value[1]);
    }

    // Act & Assert
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArray.length));
    for (char[] chars : methodPairsArray) {
      try {
        assertEquals(methodSFS.getChar(String.valueOf(chars[0])), chars[1]);
        assertEquals(chars[1], methodSFS.getChar(String.valueOf(chars[0]), '5'));
      } catch (FSParseException aException) {
        fail("Not expected exception thrown : " + aException.getMessage());
      }
    }
  }

  /**
   * Tests put(String,short) and [getShort(String)|getShort(String,short)] methods consistency. The
   * default value (returned if the key is not found) is set to a not present short value, so we are
   * sure if it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringShort() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    short[][] methodPairsArray = {{1, 1}, {2, 2}, {3, 3}, {4, 4}};
    for (short[] value : methodPairsArray) {
      methodSFS.put(Short.toString(value[0]), value[1]);
    }

    // Act & Assert
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArray.length));
    for (short[] shorts : methodPairsArray) {
      try {
        assertEquals(methodSFS.getShort(Short.toString(shorts[0])), shorts[1]);
        assertEquals(methodSFS.getShort(Short.toString(shorts[0]), (short) 5), shorts[1]);
      } catch (FSParseException aException) {
        fail("Not expected exception thrown : " + aException.getMessage());
      }
    }
  }

  /**
   * Tests put(String,double) and [getDouble(String)|getDouble(String,double)] methods consistency.
   * The default value (returned if the key is not found) is set to a not present double value, so
   * we are sure if it finds the right value or not (and does not use the default).
   */
  @Test
  void testPut_StringDouble() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    double[][] methodPairsArray = {{1, 1}, {2, 2}, {3, 3}, {4, 4}};
    for (double[] value : methodPairsArray) {
      methodSFS.put(Double.toString(value[0]), value[1]);
    }

    // Act & Assert
    assertTrue(checkSimpleFieldSetSize(methodSFS, methodPairsArray.length));
    for (double[] doubles : methodPairsArray) {
      try {
        // there is no assertEquals(Double,Double) so we are obliged to do this way -_-
        assertEquals(
            0, Double.compare(methodSFS.getDouble(Double.toString(doubles[0])), doubles[1]));
        assertEquals(
            0, Double.compare(methodSFS.getDouble(Double.toString(doubles[0]), 5), doubles[1]));
      } catch (FSParseException aException) {
        fail("Not expected exception thrown : " + aException.getMessage());
      }
    }
  }

  /**
   * Tests SimpleFieldSet(String,boolean,boolean) constructor, with simple and border cases of the
   * canonical form.
   */
  @Test
  void testSimpleFieldSet_StringBooleanBoolean() {
    // Arrange
    String[][] methodStringPairs = SAMPLE_STRING_PAIRS;
    String methodStringToParse = sfsReadyString(methodStringPairs);

    // Act
    try {
      SimpleFieldSet methodSFS = new SimpleFieldSet(methodStringToParse, false, false, false);

      // Assert
      for (String[] methodStringPair : methodStringPairs) {
        assertEquals(methodSFS.get(methodStringPair[0]), methodStringPair[1]);
      }
    } catch (IOException aException) {
      fail("Not expected exception thrown : " + aException.getMessage());
    }
  }

  /**
   * Tests SimpleFieldSet(BufferedReader,boolean,boolean) constructor, with simple and border cases
   * of the canonical form.
   */
  @Test
  void testSimpleFieldSet_BufferedReaderBooleanBoolean() {
    // Arrange
    String[][] methodStringPairs = SAMPLE_STRING_PAIRS;
    BufferedReader methodBufferedReader =
        new BufferedReader(new StringReader(sfsReadyString(methodStringPairs)));
    // Act
    try {
      SimpleFieldSet methodSFS = new SimpleFieldSet(methodBufferedReader, false, false);
      // Assert
      for (String[] methodStringPair : methodStringPairs) {
        assertEquals(methodSFS.get(methodStringPair[0]), methodStringPair[1]);
      }
    } catch (IOException aException) {
      fail("Not expected exception thrown : " + aException.getMessage());
    }
  }

  /**
   * Tests SimpleFieldSet(SimpleFieldSet) constructor, with simple and border cases of the canonical
   * form.
   */
  @Test
  void testSimpleFieldSet_SimpleFieldSet() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(sfsFromSampleStringPairs());

    // Act & Assert
    for (String[] methodStringPair : SAMPLE_STRING_PAIRS) {
      assertEquals(methodSFS.get(methodStringPair[0]), methodStringPair[1]);
    }
  }

  /** Tests {get,set}EndMarker(String) methods using them after a String parsing */
  @Test
  void testEndMarker() {
    // Arrange
    String methodEndMarker = "ANOTHER-ENDING";
    String methodStringToParse = sfsReadyString(SAMPLE_STRING_PAIRS);
    try {
      SimpleFieldSet methodSFS = new SimpleFieldSet(methodStringToParse, false, false, false);
      // Assert initial
      assertEquals(SAMPLE_END_MARKER, methodSFS.getEndMarker());
      // Act
      methodSFS.setEndMarker(methodEndMarker);
      // Assert updated
      assertEquals(methodEndMarker, methodSFS.getEndMarker());
    } catch (IOException aException) {
      fail("Not expected exception thrown : " + aException.getMessage());
    }
  }

  /** Tests isEmpty() method. */
  @Test
  void testIsEmpty() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Assert non-empty
    assertFalse(methodSFS.isEmpty());
    // Arrange empty
    methodSFS = new SimpleFieldSet(true);
    // Assert empty
    assertTrue(methodSFS.isEmpty());
  }

  /**
   * Tests directSubsetNameIterator() method. It uses SAMPLE_STRING_PAIRS and for this reason the
   * expected subset is "foo".
   */
  @Test
  void testDirectSubsetNameIterator() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    String expectedSubset = SAMPLE_STRING_PAIRS[0][0]; // "foo"
    // Act
    Iterator<String> methodIter = methodSFS.directSubsetNameIterator();
    // Assert
    while (methodIter.hasNext()) {
      assertEquals(methodIter.next(), expectedSubset);
    }
    // Arrange empty SFS
    methodSFS = new SimpleFieldSet(true);
    // Act & Assert: should be null when no subsets
    methodIter = methodSFS.directSubsetNameIterator();
    assertNull(methodIter);
  }

  /** Tests nameOfDirectSubsets() method. */
  @Test
  void testNamesOfDirectSubsets() {
    // Arrange
    String[] expectedResult = {SAMPLE_STRING_PAIRS[0][0]};
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act & Assert
    assertArrayEquals(methodSFS.namesOfDirectSubsets(), expectedResult);

    // Arrange empty
    methodSFS = new SimpleFieldSet(true);
    // Act & Assert
    assertArrayEquals(new String[0], methodSFS.namesOfDirectSubsets());
  }

  /** Test the putOverwrite(String,String) method. */
  @Test
  void testPutOverwrite_String() {
    // Arrange
    String methodKey = "foo.bar";
    String[] methodValues = {"boo", "bar", "zoo"};
    String expectedResult = "zoo";
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // Act
    for (String methodValue : methodValues) {
      methodSFS.putOverwrite(methodKey, methodValue);
    }
    // Assert
    assertEquals(expectedResult, methodSFS.get(methodKey));
  }

  /** Test the putOverwrite(String,String[]) method. */
  @Test
  void testPutOverwrite_StringArray() {
    // Arrange
    String methodKey = "foo.bar";
    String[] methodValues = {"boo", "bar", "zoo"};
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // Act
    methodSFS.putOverwrite(methodKey, methodValues);
    // Assert
    assertArrayEquals(methodSFS.getAll(methodKey), methodValues);
  }

  /** Test the putAppend(String,String) method. */
  @Test
  void testPutAppend() {
    // Arrange
    String methodKey = "foo.bar";
    String[] methodValues = {"boo", "bar", "zoo"};
    String expectedResult =
        "boo" + SimpleFieldSet.MULTI_VALUE_CHAR + "bar" + SimpleFieldSet.MULTI_VALUE_CHAR + "zoo";
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // Act
    for (String methodValue : methodValues) {
      methodSFS.putAppend(methodKey, methodValue);
    }
    // Assert
    assertEquals(expectedResult, methodSFS.get(methodKey));
  }

  /** Tests the getAll(String) method. */
  @Test
  void testGetAll() {
    // Arrange
    String methodKey = "foo.bar";
    String[] methodValues = {"boo", "bar", "zoo"};
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // Act
    for (String methodValue : methodValues) {
      methodSFS.putAppend(methodKey, methodValue);
    }
    // Assert
    assertArrayEquals(methodSFS.getAll(methodKey), methodValues);
  }

  /** Tests the getIntArray(String) method */
  @Test
  void testGetIntArray() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    String keyPrefix = "foo";
    for (int i = 0; i < 15; i++) {
      methodSFS.putAppend(keyPrefix, String.valueOf(i));
    }
    // Act
    int[] result = methodSFS.getIntArray(keyPrefix);
    // Assert
    for (int i = 0; i < 15; i++) {
      assertEquals(result[i], i);
    }
  }

  /** Tests the getDoubleArray(String) method */
  @Test
  void testGetDoubleArray() {
    // Arrange
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    String keyPrefix = "foo";
    for (int i = 0; i < 15; i++) {
      methodSFS.putAppend(keyPrefix, String.valueOf((double) i));
    }
    // Act
    double[] result = methodSFS.getDoubleArray(keyPrefix);
    // Assert
    for (int i = 0; i < 15; i++) {
      assertEquals(result[i], i, 0.0);
    }
  }

  /** Tests removeValue(String) method */
  @Test
  void testRemoveValue() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act
    methodSFS.removeValue("foo");
    // Assert
    assertNull(methodSFS.get(SAMPLE_STRING_PAIRS[0][0]));
    for (int i = 1; i < SAMPLE_STRING_PAIRS.length; i++) {
      assertEquals(methodSFS.get(SAMPLE_STRING_PAIRS[i][0]), SAMPLE_STRING_PAIRS[i][1]);
    }
  }

  /** Tests removeSubset(String) method */
  @Test
  void testRemoveSubset() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act
    methodSFS.removeSubset("foo");
    // Assert
    for (int i = 1; i < 4; i++) {
      assertNull(methodSFS.get(SAMPLE_STRING_PAIRS[i][0]));
    }
    assertEquals(SAMPLE_STRING_PAIRS[0][1], methodSFS.get(SAMPLE_STRING_PAIRS[0][0]));
    for (int i = 4; i < 6; i++) {
      assertEquals(methodSFS.get(SAMPLE_STRING_PAIRS[i][0]), SAMPLE_STRING_PAIRS[i][1]);
    }
  }

  /**
   * Tests the Iterator given for the SimpleFieldSet class. It tests hasNext() and next() methods.
   */
  @Test
  void testKeyIterator() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act
    Iterator<String> itr = methodSFS.keyIterator();
    // Assert
    assertTrue(areAllContainedKeys("", itr));
  }

  /** Tests the Iterator created using prefix given for the SimpleFieldSet class */
  @Test
  void testKeyIterator_String() {
    // Arrange
    String methodPrefix = "bob";
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act
    Iterator<String> itr = methodSFS.keyIterator(methodPrefix);
    // Assert
    assertTrue(areAllContainedKeys(methodPrefix, itr));
  }

  /**
   * Tests the toplevelIterator given for the SimpleFieldSet class. It tests hasNext() and next()
   * methods.
   */
  @Test
  void testToplevelKeyIterator() {
    // Arrange
    SimpleFieldSet methodSFS = sfsFromSampleStringPairs();
    // Act
    Iterator<String> itr = methodSFS.toplevelKeyIterator();
    // Assert
    for (int i = 0; i < 3; i++) {
      assertTrue(itr.hasNext());
      assertTrue(isAKey("", itr.next()));
    }
    assertFalse(itr.hasNext());
  }

  @Test
  void testKeyIterationPastEnd() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putOverwrite("test", "test");

    // Act
    Iterator<String> keyIterator = sfs.keyIterator();
    String first = keyIterator.next();

    // Assert
    assertEquals("test", first);
    assertThrows(NoSuchElementException.class, keyIterator::next);
  }

  @Test
  void testBase64() throws IOException {
    // Arrange
    // Act & Assert
    checkBase64("test", " ", "IA");
    for (String[] s : SAMPLE_STRING_PAIRS) {
      String evilValue = "=" + s[1];
      String base64 = Base64.encodeUTF8(evilValue);
      checkBase64(s[0], evilValue, base64);
    }
  }

  @Test
  void testEmptyValue() throws IOException {
    // Arrange
    String written = "foo.blah=\nEnd\n";
    // Act
    LineReader r = Readers.fromBufferedReader(new BufferedReader(new StringReader(written)));
    SimpleFieldSet sfsCheck = new SimpleFieldSet(r, 1024, 1024, true, false, true, false);
    // Assert
    assertTrue(sfsCheck.get("foo.blah").isEmpty());
    // Act again with allowBase64 true
    r = Readers.fromBufferedReader(new BufferedReader(new StringReader(written)));
    sfsCheck = new SimpleFieldSet(r, 1024, 1024, true, false, true, true);
    // Assert
    assertTrue(sfsCheck.get("foo.blah").isEmpty());
  }

  @Test
  void testSplit() {
    // Arrange/Act/Assert
    assertArrayEquals(new String[] {"blah"}, SimpleFieldSet.split("blah"));
    assertArrayEquals(new String[] {"blah", " blah"}, SimpleFieldSet.split("blah; blah"));
    assertArrayEquals(new String[] {"blah", "1", "2"}, SimpleFieldSet.split("blah;1;2"));
    assertArrayEquals(new String[] {"blah", "1", "2", ""}, SimpleFieldSet.split("blah;1;2;"));
    assertArrayEquals(new String[] {"blah", "1", "2", "", ""}, SimpleFieldSet.split("blah;1;2;;"));
    assertArrayEquals(
        new String[] {"", "blah", "1", "2", "", ""}, SimpleFieldSet.split(";blah;1;2;;"));
    assertArrayEquals(
        new String[] {"", "", "blah", "1", "2", "", ""}, SimpleFieldSet.split(";;blah;1;2;;"));
    assertArrayEquals(new String[] {"", "", ""}, SimpleFieldSet.split(";;;"));
  }

  // This fixes https://freenet.mantishub.io/view.php?id=7197.
  @Test
  void directSubsetsReturnsEmptyMapWhenSubsetsIsNotInitialized() {
    // Arrange
    SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
    // Act & Assert
    assertThat(simpleFieldSet.directSubsets(), anEmptyMap());
  }

  /**
   * It puts key-value pairs in a SimpleFieldSet and verify if it can do the correspondent get
   * correctly.
   *
   * @param aPairsArray array of key/value pairs to insert and then verify via get()
   * @return true if it is correct
   */
  private boolean checkPutAndGetPairs(String[][] aPairsArray) {
    boolean retValue = true;
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // putting values
    for (String[] value : aPairsArray) {
      methodSFS.putSingle(value[0], value[1]);
    }
    // getting values
    for (String[] strings : aPairsArray) {
      retValue &= methodSFS.get(strings[0]).equals(strings[1]);
    }
    retValue &= checkSimpleFieldSetSize(methodSFS, aPairsArray.length);
    return retValue;
  }

  /**
   * It creates an SFS from the SAMPLE_STRING_PAIRS and putting a suffix after every value
   *
   * @param aSuffix to put after every value
   * @return the SimpleFieldSet created
   */
  private SimpleFieldSet sfsFromStringPairs(String aSuffix) {
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    // creating new
    for (String[] sampleStringPair : SAMPLE_STRING_PAIRS) {
      methodSFS.putSingle(sampleStringPair[0], sampleStringPair[1] + aSuffix);
    }
    return methodSFS;
  }

  /**
   * Checks if the provided SimpleFieldSet has the right size
   *
   * @param aSimpleFieldSet the SimpleFieldSet whose number of keys is checked
   * @param expectedSize the expected number of keys returned by keyIterator()
   * @return true if the size is the expected
   */
  private boolean checkSimpleFieldSetSize(SimpleFieldSet aSimpleFieldSet, int expectedSize) {
    int actualSize = 0;
    Iterator<String> methodKeyIterator = aSimpleFieldSet.keyIterator();
    while (methodKeyIterator.hasNext()) {
      methodKeyIterator.next();
      actualSize++;
    }
    return expectedSize == actualSize;
  }

  /**
   * Generates a string for the SFS parser in the canonical form: key=value END
   *
   * @param aStringPairsArray array of key/value pairs used to build the canonical string
   * @return a String ready to be read by an SFS parser
   */
  private String sfsReadyString(String[][] aStringPairsArray) {

    StringBuilder methodStringToReturn = new StringBuilder();
    for (String[] strings : aStringPairsArray) {
      methodStringToReturn
          .append(strings[0])
          .append(KEY_VALUE_SEPARATOR)
          .append(strings[1])
          .append('\n');
    }
    methodStringToReturn.append(SAMPLE_END_MARKER);
    return methodStringToReturn.toString();
  }

  /**
   * Generates a SimpleFieldSet using the SAMPLE_STRING_PAIRS and sfs put method
   *
   * @return a SimpleFieldSet
   */
  private SimpleFieldSet sfsFromSampleStringPairs() {
    SimpleFieldSet methodSFS = new SimpleFieldSet(true);
    for (String[] sampleStringPair : SAMPLE_STRING_PAIRS) {
      methodSFS.putSingle(sampleStringPair[0], sampleStringPair[1]);
    }
    assertTrue(checkSimpleFieldSetSize(methodSFS, SAMPLE_STRING_PAIRS.length));
    return methodSFS;
  }

  /**
   * Checks whether a given key (optionally prefixed) exists in SAMPLE_STRING_PAIRS. We consider
   * that keys are stored in {@code SAMPLE_STRING_PAIRS[x][0]}.
   *
   * @param aPrefix prefix to put before the found key when comparing
   * @param aKey the key to search for
   * @return true if the key exists (with the optional prefix), false otherwise
   */
  private boolean isAKey(String aPrefix, String aKey) {
    for (String[] strings : SAMPLE_STRING_PAIRS) {
      if (aKey.equals(aPrefix + strings[0])) {
        return true;
      }
    }
    return false;
  }

  /**
   * Verifies that all keys provided by the iterator match the keys in SAMPLE_STRING_PAIRS (with an
   * optional prefix). This exercises both {@link Iterator#hasNext()} and {@link Iterator#next()}.
   *
   * @param aPrefix prefix to put before each expected key
   * @param aIterator iterator over keys to validate
   * @return true if the iterator yields exactly the expected keys
   */
  private boolean areAllContainedKeys(String aPrefix, Iterator<String> aIterator) {
    boolean retValue = true;
    int actualLength = 0;
    while (aIterator.hasNext()) {
      actualLength++;
      retValue &= isAKey(aPrefix, aIterator.next());
    }
    retValue &= (actualLength == SAMPLE_STRING_PAIRS.length);
    return retValue;
  }

  private void checkBase64(String key, String value, String base64Value) throws IOException {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(key, value);
    assertEquals(sfs.toOrderedString(), key + "=" + value + "\nEnd\n");
    StringWriter sw = new StringWriter();
    sfs.writeTo(sw, "", false, true);
    String written = sw.toString();
    assertEquals(written, key + "==" + base64Value + "\nEnd\n");
    LineReader r = Readers.fromBufferedReader(new BufferedReader(new StringReader(written)));
    SimpleFieldSet sfsCheck = new SimpleFieldSet(r, 1024, 1024, true, false, true, true);
    assertEquals(sfsCheck.get(key), value);
  }

  private static final char KEY_VALUE_SEPARATOR = '=';
  /* A double string array used across all tests
   * it must not be changed in order to perform tests
   * correctly */
  private static final String[][] SAMPLE_STRING_PAIRS = {
    // directSubset
    {"foo", "bar"},
    {"foo.bar", "foobar"},
    {"foo.bar.foo", "foobar"},
    {"foo.bar.boo.far", "foobar"},
    {"foo2", "foobar.fooboo.foofar.foofoo"},
    {"foo3", KEY_VALUE_SEPARATOR + "bar"}
  };
  private static final String SAMPLE_END_MARKER = "END";

  // --- New tests adding coverage for edge cases and error paths ---

  @Test
  @SuppressWarnings("java:S100") // method_whenCondition_expectOutcome naming
  void directMaps_andSets_whenMixedLevels_expectOnlyTopLevelAndUnmodifiable() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("top", "1");
    sfs.putSingle("nest.a", "2");
    sfs.putSingle("nest.b", "3");

    // Act
    Map<String, String> direct = sfs.directKeyValues();
    Set<String> directKeys = sfs.directKeys();
    Map<String, SimpleFieldSet> subsets = sfs.directSubsets();

    // Assert: contents
    assertEquals(Collections.singletonMap("top", "1"), direct);
    assertEquals(Collections.singleton("top"), directKeys);
    assertTrue(subsets.containsKey("nest"));
    assertEquals("2", subsets.get("nest").get("a"));

    // Assert: unmodifiable
    assertThrows(UnsupportedOperationException.class, () -> direct.put("x", "y"));
    assertThrows(UnsupportedOperationException.class, () -> directKeys.add("x"));
    // Create argument outside to ensure the lambda has a single potentially throwing call
    SimpleFieldSet newSubset = new SimpleFieldSet(true);
    assertThrows(UnsupportedOperationException.class, () -> subsets.put("x", newSubset));
  }

  @Test
  @SuppressWarnings("java:S100")
  void tput_whenNullOrEmpty_expectNoChange() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("a", "1");

    // Act
    sfs.tput("b", null); // no-op
    sfs.tput("c", new SimpleFieldSet(true)); // empty = no-op

    // Assert
    assertEquals("1", sfs.get("a"));
    assertNull(sfs.get("b.x"));
    assertNull(sfs.get("c.x"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void putSubset_whenDuplicateKey_expectIllegalArgumentException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    SimpleFieldSet child = new SimpleFieldSet(true);
    child.putSingle("k", "v");
    sfs.put("dup", child);

    // Act + Assert
    SimpleFieldSet another = new SimpleFieldSet(true);
    another.putSingle("z", "y");
    assertThrows(IllegalArgumentException.class, () -> sfs.put("dup", another));
  }

  @Test
  @SuppressWarnings("java:S100")
  void putAppend_whenValueContainsMultiValueChar_expectIllegalArgumentException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> sfs.putAppend("k", "a;b"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void putWithNewline_whenAlwaysUseBase64False_expectIllegalArgumentException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true, false);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> sfs.putOverwrite("k", "line1\nline2"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void putWithNewline_whenAlwaysUseBase64True_expectBase64OnWrite() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true, true);
    String valueWithNewline = "line1\nline2";
    sfs.putOverwrite("k", valueWithNewline);

    // Act
    String ordered = sfs.toOrderedString();

    // Assert: should use == and be decodable
    String expectedEncoded = Base64.encodeUTF8(valueWithNewline);
    assertEquals("k==" + expectedEncoded + "\nEnd\n", ordered);
  }

  @Test
  @SuppressWarnings("java:S100")
  void getBoolean_whenInvalid_expectFSParseException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("flag", "notABoolean");

    // Act + Assert
    assertThrows(FSParseException.class, () -> sfs.getBoolean("flag"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getString_whenMissing_expectFSParseException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    // Act + Assert
    assertThrows(FSParseException.class, () -> sfs.getString("missing"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getChar_whenInvalidLength_expectFSParseException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("ch", "ab");

    // Act + Assert
    assertThrows(FSParseException.class, () -> sfs.getChar("ch"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getByteArray_whenInvalidBase64_expectFSParseException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("bytes", "not-base64!!!");

    // Act + Assert
    assertThrows(FSParseException.class, () -> sfs.getByteArray("bytes"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getSubset_whenMissing_expectFSParseException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("a.b", "1");

    // Act + Assert
    assertThrows(FSParseException.class, () -> sfs.getSubset("missing"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void writeTo_andReadFrom_roundTrip_expectSameValues() throws IOException {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.setHeader("hdr1", "hdr2");
    sfs.putSingle("x", "1 2");
    sfs.putSingle("nest.k", "v");

    // Act
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    sfs.writeTo(bos);
    byte[] data = bos.toByteArray();

    SimpleFieldSet read = SimpleFieldSet.readFrom(new ByteArrayInputStream(data), false, true);

    // Assert
    assertEquals("1 2", read.get("x"));
    assertEquals("v", read.get("nest.k"));
    assertArrayEquals(new String[] {"hdr1", "hdr2"}, read.getHeader());
  }

  @Test
  @SuppressWarnings("java:S100")
  void writeToBigBuffer_andReadFrom_roundTrip_expectSameValues() throws IOException {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("a", "alpha");
    sfs.putSingle("b.c", "charlie");

    // Act
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    sfs.writeToBigBuffer(bos);
    SimpleFieldSet read =
        SimpleFieldSet.readFrom(new ByteArrayInputStream(bos.toByteArray()), false, true);

    // Assert
    assertEquals("alpha", read.get("a"));
    assertEquals("charlie", read.get("b.c"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void putEncoded_andGetAllEncoded_whenRoundTrip_expectOriginalStrings() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    String[] original = new String[] {"", "a;b", "with space", "=equals=", "new\nline"};

    // Act
    sfs.putEncoded("enc", original);
    String[] decoded = sfs.getAllEncoded("enc");

    // Assert
    assertArrayEquals(original, decoded);
  }

  @Test
  @SuppressWarnings("java:S100")
  void toOrderedStringWithBase64_whenSpecialChars_expectDoubleEqualsAndDecodable() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true, true);
    String val = "value with spaces and = and . and ;";
    sfs.putOverwrite("k", val);

    // Act
    String out = sfs.toOrderedStringWithBase64();

    // Assert
    String expected = "k==" + Base64.encodeUTF8(val) + "\nEnd\n";
    assertEquals(expected, out);
  }

  @Test
  @SuppressWarnings("java:S100")
  void keyIterator_remove_expectUnsupportedOperationException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("a", "1");
    Iterator<String> it = sfs.keyIterator();
    it.next();

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, it::remove);
  }

  @Test
  @SuppressWarnings("java:S100")
  void readFrom_StringArray_whenValid_expectParsedValues() throws IOException {
    // Arrange
    String[] lines = new String[] {"a=1", "b.c=2", SAMPLE_END_MARKER};

    // Act
    SimpleFieldSet sfs = new SimpleFieldSet(lines, false, true, false);

    // Assert
    assertEquals("1", sfs.get("a"));
    assertEquals("2", sfs.get("b.c"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void readWithInlineComment_insideBody_expectSubsequentPairsParsed() throws IOException {
    // Arrange
    String s = "a=1\n# comment\nb=2\nEnd\n";
    BufferedReader br = new BufferedReader(new StringReader(s));

    // Act
    SimpleFieldSet sfs = new SimpleFieldSet(br, false, true);

    // Assert
    assertEquals("1", sfs.get("a"));
    assertEquals("2", sfs.get("b"));
    assertEquals("End", sfs.getEndMarker());
    assertNull(sfs.getHeader());
  }
}

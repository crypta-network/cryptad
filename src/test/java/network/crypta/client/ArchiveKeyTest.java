package network.crypta.client;

import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
class ArchiveKeyTest {

  private static FreenetURI ksk(String name) {
    // Simple KSK (no routing/crypto keys) is sufficient for ArchiveKey tests
    return new FreenetURI("KSK", name);
  }

  @Test
  @DisplayName("equals: same instance -> true")
  void equals_whenSameInstance_expectTrue() {
    ArchiveKey a = new ArchiveKey(ksk("doc"), "file.txt");

    //noinspection EqualsWithItself
    assertEquals(a, a);
  }

  @Test
  @DisplayName("equals: null -> false")
  @SuppressWarnings("java:S5785")
  void equals_whenNull_expectFalse() {
    ArchiveKey a = new ArchiveKey(ksk("doc"), "file.txt");

    //noinspection SimplifiableAssertion,ConstantValue
    assertFalse(a.equals(null));
  }

  @Test
  @DisplayName("equals: different type -> false")
  @SuppressWarnings("java:S5785")
  void equals_whenDifferentClass_expectFalse() {
    ArchiveKey a = new ArchiveKey(ksk("doc"), "file.txt");

    //noinspection SimplifiableAssertion,EqualsBetweenInconvertibleTypes
    assertFalse(a.equals("not-an-archive-key"));
  }

  @Test
  @DisplayName("equals: same key and filename -> true (symmetry)")
  void equals_whenSameFields_expectTrueAndSymmetric() {
    FreenetURI key = ksk("doc");
    ArchiveKey a1 = new ArchiveKey(key, "file.txt");
    ArchiveKey a2 = new ArchiveKey(new FreenetURI(key), "file.txt");

    assertEquals(a1, a2);
    assertEquals(a2, a1);
  }

  @Test
  @DisplayName("equals: different key -> false")
  void equals_whenDifferentKey_expectFalse() {
    ArchiveKey a1 = new ArchiveKey(ksk("doc1"), "file.txt");
    ArchiveKey a2 = new ArchiveKey(ksk("doc2"), "file.txt");

    assertNotEquals(a1, a2);
  }

  @Test
  @DisplayName("equals: different filename -> false")
  void equals_whenDifferentFilename_expectFalse() {
    FreenetURI key = ksk("doc");
    ArchiveKey a1 = new ArchiveKey(key, "file1.txt");
    ArchiveKey a2 = new ArchiveKey(new FreenetURI(key), "file2.txt");

    assertNotEquals(a1, a2);
  }

  @Test
  @DisplayName("hashCode: equal objects -> same hash")
  void hashCode_whenEqualObjects_expectSameHash() {
    FreenetURI key = ksk("doc");
    ArchiveKey a1 = new ArchiveKey(key, "file.txt");
    ArchiveKey a2 = new ArchiveKey(new FreenetURI(key), "file.txt");

    assertEquals(a1.hashCode(), a2.hashCode());
  }

  @Test
  @DisplayName("hashCode: null key -> throws NPE")
  void hashCode_whenNullKey_expectThrowsNPE() {
    ArchiveKey a = new ArchiveKey(null, "file.txt");

    assertThrows(NullPointerException.class, a::hashCode);
  }

  @Test
  @DisplayName("hashCode: null filename -> throws NPE")
  void hashCode_whenNullFilename_expectThrowsNPE() {
    ArchiveKey a = new ArchiveKey(ksk("doc"), null);

    assertThrows(NullPointerException.class, a::hashCode);
  }

  @Test
  @DisplayName("equals: other has null key -> throws NPE (asymmetric null handling)")
  void equals_whenOtherHasNullKey_expectThrowsNPE() {
    ArchiveKey lhs = new ArchiveKey(ksk("doc"), "file.txt");
    ArchiveKey rhs = new ArchiveKey(null, "file.txt");

    assertThrows(NullPointerException.class, () -> lhs.equals(rhs));
  }

  @Test
  @DisplayName("equals: other has null filename -> throws NPE (asymmetric null handling)")
  void equals_whenOtherHasNullFilename_expectThrowsNPE() {
    ArchiveKey lhs = new ArchiveKey(ksk("doc"), "file.txt");
    ArchiveKey rhs = new ArchiveKey(ksk("doc"), null);

    assertThrows(NullPointerException.class, () -> lhs.equals(rhs));
  }

  @Test
  @DisplayName("toString: key + ':' + filename")
  void toString_whenValid_expectKeyColonFilename() {
    FreenetURI key = ksk("doc");
    String filename = "file.txt";
    ArchiveKey a = new ArchiveKey(key, filename);

    String expected = key + ":" + filename;
    assertEquals(expected, a.toString());
  }

  @Test
  @DisplayName("toString: null parts -> contains 'null'")
  void toString_whenNullParts_expectContainsNullLiteral() {
    ArchiveKey a1 = new ArchiveKey(null, "file.txt");
    ArchiveKey a2 = new ArchiveKey(ksk("doc"), null);

    assertTrue(a1.toString().startsWith("null:"));
    assertTrue(a2.toString().endsWith(":null"));
  }
}

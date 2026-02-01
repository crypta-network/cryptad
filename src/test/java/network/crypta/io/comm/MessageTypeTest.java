package network.crypta.io.comm;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import network.crypta.support.ShortBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Method naming uses AAA style: method_whenCondition_expectOutcome
class MessageTypeTest {

  private final List<MessageType> toCleanup = new ArrayList<>();
  private static final String NAME_NOT_NULL_MSG =
      "findAvailableName must return a non-null unique name";

  @AfterEach
  void tearDown() {
    // Ensure we unregister any types we created so tests remain isolated.
    for (MessageType mt : toCleanup) {
      try {
        mt.unregister();
      } catch (Throwable _) {
        // best-effort cleanup
      }
    }
    toCleanup.clear();
  }

  @Test
  void constructor_andRegistry_registersAndUnregisters() {
    String name =
        findAvailableName(
            "MT_Test_Unique_Alpha",
            "MT_Test_Unique_Beta",
            "MT_Test_Unique_Gamma",
            "MT_Test_Unique_Delta");

    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    Integer id = name.hashCode();
    assertSame(
        mt, MessageType.getSpec(id, true), "Spec should be retrievable by id after construction");

    mt.unregister();
    toCleanup.remove(mt);
    assertNull(MessageType.getSpec(id, true), "Spec should be absent after unregister");
  }

  @Test
  void constructor_whenDuplicateSameName_expectRuntimeException() {
    String name =
        findAvailableName(
            "MT_Test_Unique_Epsilon",
            "MT_Test_Unique_Zeta",
            "MT_Test_Unique_Eta",
            "MT_Test_Unique_Theta");

    MessageType first = new MessageType(name, (short) 1);
    toCleanup.add(first);

    RuntimeException ex =
        assertThrows(RuntimeException.class, () -> new MessageType(name, (short) 1));
    assertTrue(
        ex.getMessage().contains("A message type by the name of "),
        "Exception message should mention duplicate");
  }

  @Test
  void addField_andTypeQueries_trackTypesAndOrder() {
    String name = findAvailableName("MT_Field_A");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    mt.addField("a", Long.class);
    mt.addField("b", String.class);
    mt.addField("c", Integer.class);

    // typeOf resolves definitions
    assertEquals(Long.class, mt.typeOf("a"));
    assertEquals(String.class, mt.typeOf("b"));
    assertEquals(Integer.class, mt.typeOf("c"));
    assertNull(mt.typeOf("nope"));

    // Ordered fields preserve insertion order
    List<String> expectedOrder = Arrays.asList("a", "b", "c");
    assertEquals(expectedOrder, mt.getOrderedFields());

    // Fields map contains exactly the declared keys
    Map<String, Class<?>> fields = mt.getFields();
    assertEquals(3, fields.size());
    assertTrue(fields.containsKey("a") && fields.containsKey("b") && fields.containsKey("c"));
  }

  @Test
  void addLinkedListField_recordsParameterType_andInsertsField() {
    String name = findAvailableName("MT_LL_A");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    mt.addLinkedListField("ll", Integer.class);

    assertEquals(List.class, mt.typeOf("ll"));
    assertEquals(Integer.class, mt.getLinkedListTypes().get("ll"));
    assertTrue(mt.getOrderedFields().contains("ll"));
  }

  @Test
  void addRoutedToNodeMessageFields_declaresExpectedSchema() {
    String name = findAvailableName("MT_Routed_Fields");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    mt.addRoutedToNodeMessageFields();

    assertEquals(Long.class, mt.typeOf(DMT.UID));
    assertEquals(Double.class, mt.typeOf(DMT.TARGET_LOCATION));
    assertEquals(Short.class, mt.typeOf(DMT.HTL));
    assertEquals(ShortBuffer.class, mt.typeOf(DMT.NODE_IDENTITY));
  }

  @Test
  void checkType_whenNullValue_returnsFalse() {
    String name = findAvailableName("MT_Check_Null");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);
    mt.addField("a", Long.class);

    assertFalse(mt.checkType("a", null));
  }

  @Test
  void checkType_whenUnknownField_throwsIllegalStateException() {
    String name = findAvailableName("MT_Check_Unknown");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    IllegalStateException ise =
        assertThrows(IllegalStateException.class, () -> mt.checkType("ghost", 1));
    assertTrue(ise.getMessage().contains("Cannot set field"));
  }

  @Test
  void checkType_whenExactClass_returnsTrue() {
    String name = findAvailableName("MT_Check_Exact");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);
    mt.addField("i", Integer.class);

    assertTrue(mt.checkType("i", 5));
  }

  @Test
  void checkType_whenAssignable_returnsTrue() {
    String name = findAvailableName("MT_Check_Assignable");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);
    mt.addField("n", Number.class);

    assertTrue(mt.checkType("n", 7));
  }

  @Test
  void checkType_whenIncompatible_returnsFalse() {
    String name = findAvailableName("MT_Check_Incompatible");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);
    mt.addField("i", Integer.class);

    assertFalse(mt.checkType("i", 10L));
  }

  @Test
  void getDefaultPriority_andFlags_reflectConstructor() {
    String name = findAvailableName("MT_PrioA");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 3, true, true);
    toCleanup.add(mt);

    assertEquals(3, mt.getDefaultPriority());
    assertTrue(mt.isInternalOnly());
    assertTrue(mt.isLossyPacketMessage());
  }

  @Test
  void equals_andHashCode_basics() {
    String nameA = findAvailableName("MT_Eq_A");
    String nameB = findAvailableName("MT_Eq_B");
    assertNotNull(nameA, NAME_NOT_NULL_MSG);
    assertNotNull(nameB, NAME_NOT_NULL_MSG);
    MessageType a = new MessageType(nameA, (short) 2);
    MessageType b = new MessageType(nameB, (short) 2);
    toCleanup.add(a);
    toCleanup.add(b);

    //noinspection EqualsWithItself
    assertEquals(a, a);
    assertNotEquals(a, b);
    assertNotEquals(null, a);
    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals("not a MessageType", a);

    assertEquals(a.getName().hashCode(), a.hashCode());
  }

  @Test
  void getMaxSize_forSimpleFields_addsFixedSizes() {
    String name = findAvailableName("MT_MaxSize_Simple");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);

    mt.addField("l", Long.class); // 8
    mt.addField("i", Integer.class); // 4
    mt.addField("b", Boolean.class); // 1
    mt.addField("s", Short.class); // 2
    mt.addField("d", Double.class); // 8
    mt.addField("y", Byte.class); // 1
    mt.addField("str", String.class); // 4 + 2*maxLen

    int maxStringLength = 10;
    int expected = 4 /* spec id */ + 8 + 4 + 1 + 2 + 8 + 1 + (4 + 2 * maxStringLength);
    assertEquals(expected, mt.getMaxSize(maxStringLength));
  }

  @Test
  void getMaxSize_whenIncludesList_throwsIllegalArgumentException() {
    String name = findAvailableName("MT_MaxSize_List");
    assertNotNull(name, NAME_NOT_NULL_MSG);
    MessageType mt = new MessageType(name, (short) 2);
    toCleanup.add(mt);
    mt.addLinkedListField("ll", Integer.class); // Serializer.length() will reject List

    assertThrows(IllegalArgumentException.class, () -> mt.getMaxSize(5));
  }

  @Test
  void getSpec_whenUnknownId_returnsNull_andOptionallyLogs() {
    // Pick an ID that is extremely unlikely to exist; also assert API returns null.
    int nonexistent = 0x7F00_1234; // Arbitrary unlikely id
    assertNull(MessageType.getSpec(nonexistent, true));
    assertNull(MessageType.getSpec(nonexistent, false));
  }

  @Test
  void constructor_whenHashCollisionDifferentName_expectRuntimeException_ifIdAvailable() {
    // Known Java String hash collisions: ("FB","Ea"), ("Aa","BB").
    List<String[]> pairs = Arrays.asList(new String[] {"FB", "Ea"}, new String[] {"Aa", "BB"});
    String[] chosen = null;
    for (String[] pair : pairs) {
      Integer id = pair[0].hashCode();
      if (MessageType.getSpec(id, true) == null) {
        chosen = pair;
        break;
      }
    }

    if (chosen == null) {
      // If every candidate hash is already used by static DMT initializers, skip deterministically.
      return; // no-op: environment already covers the branch; duplicate-name test still covers
      // behavior
    }

    MessageType first = new MessageType(chosen[0], (short) 1);
    toCleanup.add(first);
    final String collidingName = chosen[1];
    RuntimeException ex =
        assertThrows(RuntimeException.class, () -> new MessageType(collidingName, (short) 1));
    assertTrue(ex.getMessage().contains("A message type by the name of "));
  }

  // Helper: choose the first name whose hash id isn't already registered by static initializers.
  private static String findAvailableName(String... candidates) {
    for (String c : candidates) {
      if (MessageType.getSpec(c.hashCode(), true) == null) return c;
    }
    // Fallback: include a long suffix to reduce collision likelihood.
    String fallback =
        "MT_Test_" + System.identityHashCode(MessageTypeTest.class) + "_" + candidates[0];
    if (MessageType.getSpec(fallback.hashCode(), true) == null) return fallback;
    fail("Unable to find an available MessageType name; please adjust candidates.");
    return null; // unreachable
  }
}

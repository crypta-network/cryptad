package network.crypta.support;

import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link Loader}.
 *
 * <p>These tests exercise happy paths and error paths of class loading and reflective
 * instantiation, including constructor selection, primitive/boxed argument handling, and exception
 * propagation.
 */
@SuppressWarnings("java:S100") // allow method names with underscores per project test naming rules
class LoaderTest {
  private static final String JLS = "java.lang.String";

  // -------- load(String) --------

  @Test
  @DisplayName("load when called twice returns same Class instance")
  void load_whenCalledTwice_returnsSameClassObject() throws ClassNotFoundException {
    Class<?> first = Loader.load(JLS);
    Class<?> second = Loader.load(JLS);
    assertSame(first, second);
  }

  @Test
  @DisplayName("load with null throws NullPointerException")
  void load_whenNameNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> Loader.load(null));
  }

  // -------- getInstance(String) (no-args) --------

  @Test
  @DisplayName("getInstance(String) for java.lang.String creates a String")
  void getInstanceString_whenClassExistsWithNoArgCtor_returnsInstance()
      throws InvocationTargetException,
          NoSuchMethodException,
          InstantiationException,
          IllegalAccessException,
          ClassNotFoundException {
    Object instance = Loader.getInstance(JLS);
    assertInstanceOf(String.class, instance);
  }

  @Test
  @DisplayName("getInstance(String) for non-existent class throws ClassNotFoundException")
  void getInstanceString_whenClassDoesNotExist_throwsClassNotFoundException() {
    assertThrows(
        ClassNotFoundException.class,
        () -> Loader.getInstance("network.crypta.support.DoesNotExist_____"));
  }

  @Test
  @DisplayName("getInstance(String) with no default constructor throws NoSuchMethodException")
  void getInstanceString_whenNoNoArgCtor_throwsNoSuchMethodException() {
    String name = "network.crypta.support.LoaderTest$NoDefaultCtor";
    assertThrows(
        NoSuchMethodException.class,
        () ->
            Loader.getInstance(
                name // no-arg variant must fail
                ));
  }

  @Test
  @DisplayName("getInstance(String) when constructor throws wraps in InvocationTargetException")
  void getInstanceString_whenCtorThrows_throwsInvocationTargetException() {
    String name = "network.crypta.support.LoaderTest$CtorThrows";
    InvocationTargetException ex =
        assertThrows(InvocationTargetException.class, () -> Loader.getInstance(name));
    assertNotNull(ex.getCause());
    assertInstanceOf(IllegalStateException.class, ex.getCause());
    assertEquals("boom", ex.getCause().getMessage());
  }

  // -------- getInstance(String, Class[], Object[]) --------

  @Test
  @DisplayName("getInstance(String, ...) with primitive arg types succeeds and sets fields")
  void getInstanceStringWithArgs_whenArgsMatchPrimitives_constructsCorrectly()
      throws InvocationTargetException,
          NoSuchMethodException,
          InstantiationException,
          IllegalAccessException,
          ClassNotFoundException {
    String name = "network.crypta.support.LoaderTest$ArgCtor";
    Object o =
        Loader.getInstance(
            name, new Class<?>[] {int.class, String.class}, new Object[] {123, "abc"});
    ArgCtor inst = (ArgCtor) o;
    assertEquals(123, inst.a);
    assertEquals("abc", inst.b);
  }

  @Test
  @DisplayName(
      "getInstance(String, ...) with boxed types in argtypes (Integer) does not match primitive"
          + " ctor")
  void getInstanceStringWithArgs_whenWrapperTypesInArgtypes_throwsNoSuchMethodException() {
    String name = "network.crypta.support.LoaderTest$ArgCtor";
    assertThrows(
        NoSuchMethodException.class,
        () ->
            Loader.getInstance(
                name, new Class<?>[] {Integer.class, String.class}, new Object[] {123, "x"}));
  }

  // -------- getInstance(Class, Class[], Object[]) --------

  @Test
  @DisplayName("getInstance(Class, ...) for abstract class throws InstantiationException")
  void getInstanceClassWithArgs_whenAbstract_throwsInstantiationException() {
    assertThrows(
        InstantiationException.class,
        () -> Loader.getInstance(AbstractType.class, new Class<?>[] {}, new Object[] {}));
  }

  @Test
  @DisplayName("getInstance(Class, ...) with wrong signature throws NoSuchMethodException")
  void getInstanceClassWithArgs_whenWrongSignature_throwsNoSuchMethodException() {
    assertThrows(
        NoSuchMethodException.class,
        () -> Loader.getInstance(ArgCtor.class, new Class<?>[] {String.class}, new Object[] {"x"}));
  }

  @Test
  @DisplayName("getInstance(Class, ...) with args length mismatch throws IllegalArgumentException")
  void getInstanceClassWithArgs_whenArgsLengthMismatch_throwsIllegalArgumentException() {
    // Correct signature is (int, String) but we pass only one argument.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Loader.getInstance(
                ArgCtor.class, new Class<?>[] {int.class, String.class}, new Object[] {42}));
  }

  @Test
  @DisplayName("getInstance(Class, ...) with wrong arg type throws IllegalArgumentException")
  void getInstanceClassWithArgs_whenWrongArgType_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Loader.getInstance(
                ArgCtor.class,
                new Class<?>[] {int.class, String.class},
                new Object[] {"notInt", "ok"}));
  }

  // ---------- Helper classes used only by these tests ----------

  /**
   * Helper type used by reflective-name tests.
   *
   * <p>This class intentionally lacks a no-arg constructor so that {@code
   * Loader.getInstance(String)} fails with {@link NoSuchMethodException} when invoked with the
   * fully qualified name of this nested type. It is referenced by name (not by direct symbol use)
   * to exercise the string-based code path; therefore it appears unused to static analysis but must
   * remain in this file.
   */
  @SuppressWarnings("unused")
  public record NoDefaultCtor(int x) {}

  /**
   * Helper type used by reflective-name tests.
   *
   * <p>Its constructor throws to validate that {@code Loader.getInstance(String)} propagates the
   * failure as an {@link InvocationTargetException}. Like {@link NoDefaultCtor}, it is resolved by
   * fully qualified name in tests and thus looks unused to static analysis, but it is required to
   * cover this error path deterministically.
   */
  @SuppressWarnings("unused")
  public static class CtorThrows {
    public CtorThrows() {
      throw new IllegalStateException("boom");
    }
  }

  public record ArgCtor(int a, String b) {}

  @SuppressWarnings("java:S5993") // public ctor is intentional to reach InstantiationException path
  public abstract static class AbstractType {
    public AbstractType() {}
  }
}

package network.crypta.clients.http.utils;

import io.pebbletemplates.pebble.extension.Function;
import io.pebbletemplates.pebble.template.EvaluationContext;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.l10n.BaseL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class L10nExtensionTest {

  private static final String L10N_PREFIX_VARIABLE = "l10nPrefix";
  private static final String LOCALIZED_VALUE = "localized";

  @Mock private BaseL10n l10n;
  @Mock private EvaluationContext context;

  @Test
  void getFunctions_whenCalled_returnsNewMapContainingL10nFunction() {
    L10nExtension extension = new L10nExtension(l10n);

    Map<String, Function> first = extension.getFunctions();
    Map<String, Function> second = extension.getFunctions();

    assertNotNull(first.get("l10n"));
    assertNotNull(second.get("l10n"));
    assertNotSame(first, second);
    assertSame(first.get("l10n"), second.get("l10n"));
  }

  @Test
  void getArgumentNames_whenCalled_returnsSinglePositionalArgumentNameZero() {
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    assertEquals(List.of("0"), function.getArgumentNames());
  }

  @ParameterizedTest
  @MethodSource("nullOrEmptyArgs")
  void execute_whenArgsNullOrEmpty_returnsLiteralNull(Map<String, Object> args) {
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Object result = function.execute(args, null, null, 0);

    assertEquals("null", result);
  }

  static Stream<Arguments> nullOrEmptyArgs() {
    return Stream.of(Arguments.of((Map<String, Object>) null), Arguments.of(Map.of()));
  }

  @ParameterizedTest
  @CsvSource({
    "0,posKey",
    "key,namedKey",
  })
  void execute_whenKeyProvidedWithoutPrefix_resolvesUsingBaseL10n(String argName, String key) {
    when(l10n.getString(key)).thenReturn(LOCALIZED_VALUE);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Object result = function.execute(Map.of(argName, key), null, null, 0);

    assertEquals(LOCALIZED_VALUE, result);
    verify(l10n).getString(key);
  }

  @Test
  void execute_whenContextPrefixProvided_prependsPrefixBeforeLookup() {
    when(context.getVariable(L10N_PREFIX_VARIABLE)).thenReturn("test.");
    when(l10n.getString("test.some.key")).thenReturn(LOCALIZED_VALUE);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Object result = function.execute(Map.of("0", "some.key"), null, context, 0);

    assertEquals(LOCALIZED_VALUE, result);
    verify(l10n).getString("test.some.key");
  }

  @Test
  void execute_whenContextPrefixIsNonString_usesToStringValue() {
    Object prefix = 123;
    when(context.getVariable(L10N_PREFIX_VARIABLE)).thenReturn(prefix);
    when(l10n.getString("123some.key")).thenReturn(LOCALIZED_VALUE);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Object result = function.execute(Map.of("0", "some.key"), null, context, 0);

    assertEquals(LOCALIZED_VALUE, result);
    verify(l10n).getString("123some.key");
  }

  @Test
  void execute_whenArgsContainBothPositionalAndNamed_usesPositional() {
    when(context.getVariable(L10N_PREFIX_VARIABLE)).thenReturn("p.");
    when(l10n.getString("p.positional")).thenReturn(LOCALIZED_VALUE);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Object result = function.execute(Map.of("0", "positional", "key", "named"), null, context, 0);

    assertEquals(LOCALIZED_VALUE, result);
    verify(l10n).getString("p.positional");
  }

  @Test
  void execute_whenArgsHaveNoRecognizedKey_usesFirstValueDeterministically() {
    when(context.getVariable(L10N_PREFIX_VARIABLE)).thenReturn("p.");
    when(l10n.getString("p.first")).thenReturn(LOCALIZED_VALUE);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Map<String, Object> args = new LinkedHashMap<>();
    args.put("unexpected", "first");
    args.put("another", "second");

    Object result = function.execute(args, null, context, 0);

    assertEquals(LOCALIZED_VALUE, result);
    verify(l10n).getString("p.first");
  }

  @Test
  void execute_whenProvidedKeyIsExplicitlyNull_returnsLiteralNull() {
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);

    Map<String, Object> args = new LinkedHashMap<>();
    args.put("0", null);

    Object result = function.execute(args, null, context, 0);

    assertEquals("null", result);
  }

  @Test
  void execute_whenBaseL10nThrows_propagatesException() {
    when(context.getVariable(L10N_PREFIX_VARIABLE)).thenReturn("p.");
    IllegalArgumentException failure = new IllegalArgumentException("bad key");
    when(l10n.getString("p.bad")).thenThrow(failure);
    L10nExtension.L10nFunction function = new L10nExtension.L10nFunction(l10n);
    Map<String, Object> args = Map.of("0", "bad");

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> function.execute(args, null, context, 0));

    assertSame(failure, thrown);
  }
}

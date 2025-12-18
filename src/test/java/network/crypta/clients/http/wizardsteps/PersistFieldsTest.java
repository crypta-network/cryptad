package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PersistFieldsTest {

  private static final String PARAM_PRESET = "preset";
  private static final String PARAM_OPENNET = "opennet";
  private static final String PARAM_SINGLE_STEP = "singlestep";
  private static final String DEFAULT_FALSE = "false";

  @Mock private HTTPRequest request;

  @Test
  void constructor_whenRequestHasParameters_expectParsedFromParams() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("LOW");
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn("true");
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(request);

    assertTrue(fields.isUsingPreset());
    assertTrue(fields.opennet);
    assertFalse(fields.isSingleStep());
    assertSame(FirstTimeWizardToadlet.WIZARD_PRESET.LOW, fields.preset);

    verify(request).getParam(PARAM_PRESET);
    verify(request).getParam(PARAM_OPENNET, DEFAULT_FALSE);
    verify(request).getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE);
    verify(request, never()).getPartAsStringFailsafe(PARAM_PRESET, 4);
    verify(request, never()).getPartAsStringFailsafe(PARAM_OPENNET, 5);
    verify(request, never()).getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5);
  }

  @Test
  void constructor_whenRequestHasNoParameters_expectParsedFromParts() {
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PARAM_PRESET, 4)).thenReturn("HIGH");
    when(request.getPartAsStringFailsafe(PARAM_OPENNET, 5)).thenReturn(DEFAULT_FALSE);
    when(request.getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5)).thenReturn("true");

    PersistFields fields = new PersistFields(request);

    assertTrue(fields.isUsingPreset());
    assertFalse(fields.opennet);
    assertTrue(fields.isSingleStep());
    assertSame(FirstTimeWizardToadlet.WIZARD_PRESET.HIGH, fields.preset);

    verify(request).getPartAsStringFailsafe(PARAM_PRESET, 4);
    verify(request).getPartAsStringFailsafe(PARAM_OPENNET, 5);
    verify(request).getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5);
    verify(request, never()).getParam(PARAM_PRESET);
    verify(request, never()).getParam(PARAM_OPENNET, DEFAULT_FALSE);
    verify(request, never()).getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE);
  }

  @Test
  void constructor_whenOpennetPassedExplicitly_expectRequestOpennetIgnored() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("LOW");
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn("true");

    PersistFields fields = new PersistFields(false, request);

    assertFalse(fields.opennet);
    assertTrue(fields.isUsingPreset());
    assertTrue(fields.isSingleStep());

    verify(request, never()).getParam(PARAM_OPENNET, DEFAULT_FALSE);
    verify(request, never()).getPartAsStringFailsafe(PARAM_OPENNET, 5);
  }

  @Test
  void constructor_whenPresetPassedExplicitly_expectRequestPresetIgnored() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn("true");
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(FirstTimeWizardToadlet.WIZARD_PRESET.HIGH, request);

    assertTrue(fields.isUsingPreset());
    assertSame(FirstTimeWizardToadlet.WIZARD_PRESET.HIGH, fields.preset);
    assertTrue(fields.opennet);
    assertFalse(fields.isSingleStep());

    verify(request, never()).getParam(PARAM_PRESET);
    verify(request, never()).getPartAsStringFailsafe(PARAM_PRESET, 4);
  }

  @Test
  void isUsingPreset_whenInvalidPreset_expectFalse() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("NOT_A_PRESET");
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(request);

    assertFalse(fields.isUsingPreset());
    assertNull(fields.preset);
  }

  @Test
  void constructor_whenPresetPartMissing_expectPresetNull() {
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PARAM_PRESET, 4)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_OPENNET, 5)).thenReturn("true");
    when(request.getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(request);

    assertFalse(fields.isUsingPreset());
    assertNull(fields.preset);
    assertTrue(fields.opennet);
    assertFalse(fields.isSingleStep());
  }

  @Test
  void constructor_whenOpennetPassedExplicitlyAndNoParameters_expectPresetAndSingleStepFromParts() {
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PARAM_PRESET, 4)).thenReturn("HIGH");
    when(request.getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5)).thenReturn("true");

    PersistFields fields = new PersistFields(true, request);

    assertTrue(fields.opennet);
    assertTrue(fields.isUsingPreset());
    assertSame(FirstTimeWizardToadlet.WIZARD_PRESET.HIGH, fields.preset);
    assertTrue(fields.isSingleStep());

    verify(request).getPartAsStringFailsafe(PARAM_PRESET, 4);
    verify(request).getPartAsStringFailsafe(PARAM_SINGLE_STEP, 5);
    verify(request, never()).getPartAsStringFailsafe(PARAM_OPENNET, 5);
    verify(request, never()).getParam(PARAM_PRESET);
    verify(request, never()).getParam(PARAM_OPENNET, DEFAULT_FALSE);
    verify(request, never()).getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE);
  }

  @Test
  void appendTo_whenNoPresetAndNotSingleStep_expectOnlyOpennetIncluded() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("NOT_A_PRESET");
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn("true");
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(request);

    String url = fields.appendTo("/wizard/?step=welcome");

    assertEquals("/wizard/?step=welcome&opennet=true", url);
  }

  @Test
  void appendTo_whenUsingPresetAndSingleStep_expectAllFieldsIncluded() {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("HIGH");
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn("true");

    PersistFields fields = new PersistFields(request);

    String url = fields.appendTo("/wizard/?step=welcome");

    assertEquals("/wizard/?step=welcome&opennet=false&preset=HIGH&singlestep=true", url);
  }

  @ParameterizedTest
  @MethodSource("booleanValuesFromParams")
  void constructor_whenBooleanParamsProvided_expectParsedAsFields(
      String opennetRaw,
      boolean expectedOpennet,
      String singleStepRaw,
      boolean expectedSingleStep) {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn("LOW");
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn(opennetRaw);
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(singleStepRaw);

    PersistFields fields = new PersistFields(request);

    assertEquals(expectedOpennet, fields.opennet);
    assertEquals(expectedSingleStep, fields.singleStep);
  }

  static Stream<Arguments> booleanValuesFromParams() {
    return Stream.of(
        Arguments.of("true", true, "true", true),
        Arguments.of("TRUE", true, "FALSE", false),
        Arguments.of(DEFAULT_FALSE, false, DEFAULT_FALSE, false),
        Arguments.of("", false, "", false),
        Arguments.of("yes", false, "no", false));
  }

  @ParameterizedTest
  @ValueSource(strings = {"LOW", "HIGH"})
  void constructor_whenPresetIsValid_expectUsingPresetIsTrue(String preset) {
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(PARAM_PRESET)).thenReturn(preset);
    when(request.getParam(PARAM_OPENNET, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);
    when(request.getParam(PARAM_SINGLE_STEP, DEFAULT_FALSE)).thenReturn(DEFAULT_FALSE);

    PersistFields fields = new PersistFields(request);

    assertTrue(fields.isUsingPreset());
  }
}

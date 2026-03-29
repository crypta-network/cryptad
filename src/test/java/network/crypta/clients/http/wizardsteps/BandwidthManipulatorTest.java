package network.crypta.clients.http.wizardsteps;

import network.crypta.compat.BandwidthIndicator;
import network.crypta.support.IllegalValueException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
class BandwidthManipulatorTest {

  @Mock private BandwidthIndicator bandwidthIndicator;

  @Test
  void detectBandwidthLimits_whenIndicatorProvidesRates_expectWizardBandwidthLimit()
      throws WizardBandwidthDetectionUnavailableException, IllegalValueException {
    when(bandwidthIndicator.getDownstreamMaxBitRate()).thenReturn(131072);
    when(bandwidthIndicator.getUpstreamMaxBitRate()).thenReturn(16384);

    WizardBandwidthLimit limit = BandwidthManipulator.detectBandwidthLimits(bandwidthIndicator);

    assertEquals(16384L, limit.downBytes());
    assertEquals(2048L, limit.upBytes());
    assertEquals("bandwidthDetected", limit.descriptionKey());
    assertFalse(limit.maybeDefault());
  }

  @Test
  void detectBandwidthLimits_whenIndicatorMissing_expectWizardUnavailableExceptionWithCause() {
    WizardBandwidthDetectionUnavailableException exception =
        assertThrows(
            WizardBandwidthDetectionUnavailableException.class,
            () -> BandwidthManipulator.detectBandwidthLimits(null));

    assertEquals("The node does not have a bandwidthIndicator.", exception.getMessage());
    assertInstanceOf(
        network.crypta.compat.bandwidth.BandwidthDetectionUnavailableException.class,
        exception.getCause());
  }

  @Test
  void detectBandwidthLimits_whenIndicatorReportsUnavailable_expectIllegalValueException() {
    when(bandwidthIndicator.getDownstreamMaxBitRate()).thenReturn(-1);
    when(bandwidthIndicator.getUpstreamMaxBitRate()).thenReturn(1);

    IllegalValueException exception =
        assertThrows(
            IllegalValueException.class,
            () -> BandwidthManipulator.detectBandwidthLimits(bandwidthIndicator));

    assertEquals("Reported unavailable.", exception.getMessage());
  }
}

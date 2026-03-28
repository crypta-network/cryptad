package network.crypta.compat.bandwidth;

import network.crypta.compat.BandwidthIndicator;
import network.crypta.support.IllegalValueException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
class BandwidthDetectionSupportTest {

  private static final int MIN_DOWNSTREAM_BITS = 8 * 8192;
  private static final int MIN_UPSTREAM_BITS = 8192;

  @Mock private BandwidthIndicator bandwidthIndicator;

  @Test
  void detectBandwidthLimits_whenIndicatorMissing_expectUnavailableException() {
    BandwidthDetectionUnavailableException exception =
        assertThrows(
            BandwidthDetectionUnavailableException.class,
            () -> BandwidthDetectionSupport.detectBandwidthLimits(null));

    assertEquals("The node does not have a bandwidthIndicator.", exception.getMessage());
  }

  @Test
  void detectBandwidthLimits_whenIndicatorReportsUnavailable_expectIllegalValueException() {
    when(bandwidthIndicator.getDownstreamMaxBitRate()).thenReturn(-1);
    when(bandwidthIndicator.getUpstreamMaxBitRate()).thenReturn(1);

    IllegalValueException exception =
        assertThrows(
            IllegalValueException.class,
            () -> BandwidthDetectionSupport.detectBandwidthLimits(bandwidthIndicator));

    assertEquals("Reported unavailable.", exception.getMessage());
  }

  @ParameterizedTest
  @CsvSource({
    "65535, 8192, 'Detected downstream of 65535 bits/s is nonsensically slow, ignoring.'",
    "65536, 8191, 'Detected upstream of 8191 bits/s is nonsensically slow, ignoring.'"
  })
  void detectBandwidthLimits_whenReportedRateIsBelowMinimum_expectIllegalValueException(
      int downstreamBits, int upstreamBits, String expectedMessage) {
    when(bandwidthIndicator.getDownstreamMaxBitRate()).thenReturn(downstreamBits);
    when(bandwidthIndicator.getUpstreamMaxBitRate()).thenReturn(upstreamBits);

    IllegalValueException exception =
        assertThrows(
            IllegalValueException.class,
            () -> BandwidthDetectionSupport.detectBandwidthLimits(bandwidthIndicator));

    assertEquals(expectedMessage, exception.getMessage());
  }

  @Test
  void detectBandwidthLimits_whenReportedRatesMeetMinimums_expectConvertedBandwidthLimit()
      throws BandwidthDetectionUnavailableException, IllegalValueException {
    when(bandwidthIndicator.getDownstreamMaxBitRate()).thenReturn(MIN_DOWNSTREAM_BITS);
    when(bandwidthIndicator.getUpstreamMaxBitRate()).thenReturn(MIN_UPSTREAM_BITS);

    BandwidthLimit limit = BandwidthDetectionSupport.detectBandwidthLimits(bandwidthIndicator);

    assertEquals(MIN_DOWNSTREAM_BITS / 8, limit.downBytes());
    assertEquals(MIN_UPSTREAM_BITS / 8, limit.upBytes());
    assertEquals("bandwidthDetected", limit.descriptionKey());
    assertFalse(limit.maybeDefault());
  }
}

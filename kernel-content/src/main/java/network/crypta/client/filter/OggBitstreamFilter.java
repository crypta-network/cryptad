package network.crypta.client.filter;

import java.io.IOException;
import network.crypta.l10n.NodeL10n;

/**
 * Base class for specific Ogg logical bitstream filters.
 *
 * <p>This type provides shared parsing and validation utilities that are common to audio/video
 * codecs transported over the Ogg container. An instance of this class (or a subclass) is bound to
 * a single logical bitstream identified by its Ogg serial number. The filter keeps a minimal state
 * — in particular, the last seen page sequence number — and performs inexpensive structural
 * validation to ensure pages arrive in order. Subclasses should override {@code parse} to apply
 * additional, codec-specific checks while delegating to this base implementation to preserve the
 * ordering invariant.
 *
 * <p>Typical usage is to detect the bitstream type from the first page via {@link
 * #getBitstreamFilter(OggPage)} and then feed later pages to the returned filter. When a structural
 * violation is detected, the filter throws a localized {@link DataFilterException} to signal an
 * invalid stream. Instances are not thread-safe and are expected to be used by a single consumer
 * per logical stream.
 *
 * <ul>
 *   <li>Tracks page sequence numbers for basic ordering validation.
 *   <li>Provides factory logic for common Ogg codecs (e.g., Vorbis, Theora).
 *   <li>Delegates codec-specific checks to subclasses extending {@code parse}.
 * </ul>
 *
 * @author sajack
 */
public class OggBitstreamFilter {
  private static final String L10N_MALFORMED_TITLE = "MalformedTitle";

  long lastPageSequenceNumber;
  final int serialNumber;
  boolean isValidStream = true;

  /**
   * Creates a new filter bound to the logical bitstream of the supplied page.
   *
   * <p>The constructor captures the page's serial number and initializes the internal ordering
   * state using the page sequence number. Subsequent calls to {@code parse} are validated against
   * this state to ensure page ordering is preserved within the same logical stream.
   *
   * @param page the first {@link OggPage} of the logical stream; must not be {@code null}. The
   *     page's serial and sequence numbers are used to initialize the filter state.
   */
  protected OggBitstreamFilter(OggPage page) {
    serialNumber = page.getSerial();
    lastPageSequenceNumber = page.getPageNumber();
  }

  /**
   * Performs minimal validation of a page in this logical bitstream.
   *
   * <p>The base implementation verifies that the page sequence number is equal to the last seen
   * value or exactly one greater, as permitted by the Ogg container. Subclasses are expected to
   * extend this method to perform codec-specific checks, and should invoke {@code
   * super.parse(page)} to retain ordering validation.
   *
   * @param page an {@link OggPage} belonging to this logical bitstream; must carry the same serial
   *     number as the filter.
   * @return the same {@link OggPage} instance after validation so callers can chain processing
   *     without additional variables.
   * @throws IOException if subclass implementations perform I/O while validating, and such an
   *     operation fails or is interrupted.
   */
  OggPage parse(OggPage page) throws IOException {
    if (!(page.getPageNumber() == lastPageSequenceNumber + 1
        || page.getPageNumber() == lastPageSequenceNumber)) {
      isValidStream = false;
      throw new DataFilterException(
          l10n(L10N_MALFORMED_TITLE), l10n(L10N_MALFORMED_TITLE), l10n("MalformedMessage"));
    }
    lastPageSequenceNumber = page.getPageNumber();
    return page;
  }

  /**
   * Creates an appropriate Ogg bitstream filter based on the supplied page.
   *
   * <p>This factory method inspects the beginning of the page's payload to identify a known codec
   * framing and returns a filter specialized for that codec. Currently, Vorbis and Theora are
   * supported. The returned filter is initialized using the page's serial and sequence numbers and
   * can immediately be used to validate later pages from the same logical stream.
   *
   * @param page the {@link OggPage} from which the bitstream type is detected; must not be {@code
   *     null}. The page should be the first (or an early) header page for reliable identification.
   * @return a codec-specific filter instance when the page matches a known codec framing, or {@code
   *     null} when the bitstream type is not recognized.
   */
  public static OggBitstreamFilter getBitstreamFilter(OggPage page) {
    for (int i = 0; i <= VorbisPacketFilter.magicNumber.length; i++) {
      if (i == VorbisPacketFilter.magicNumber.length) return new VorbisBitstreamFilter(page);
      if (page.payload.length < i + 1 || page.payload[i + 1] != VorbisPacketFilter.magicNumber[i])
        break;
    }
    for (int i = 0; i <= TheoraPacketFilter.magicNumber.length; i++) {
      if (i == TheoraPacketFilter.magicNumber.length) return new TheoraBitstreamFilter(page);
      if (page.payload.length < i + 1 || page.payload[i + 1] != TheoraPacketFilter.magicNumber[i])
        break;
    }
    return null;
  }

  /**
   * Marks this filter's stream as invalid and signals the failure.
   *
   * <p>Subclasses should invoke this method when they detect a structural or semantic violation of
   * the bitstream format. The method sets the internal validity flag to {@code false} and throws a
   * {@link DataFilterException} carrying localized title and message strings suitable for user
   * display.
   *
   * @throws DataFilterException always thrown to indicate that the bitstream is malformed and no
   *     further parsing should continue on this filter instance.
   */
  protected void invalidate() throws DataFilterException {
    isValidStream = false;
    throw new DataFilterException(
        l10n(L10N_MALFORMED_TITLE), l10n(L10N_MALFORMED_TITLE), l10n("MalformedMessage"));
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(getClass().getSimpleName() + "." + key);
  }
}

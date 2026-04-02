package network.crypta.client;

import org.apache.commons.lang3.mutable.MutableBoolean;

/**
 * Captures per-extraction derived state used across archive processing helpers.
 *
 * <p>The state bundles the immutable input and element request parameters together with mutable
 * flags and derived values computed during extraction. It is created inside {@link
 * ArchiveManager#extractToCache(ArchiveExtractionInput, ArchiveElementRequest)} and should only be
 * used within a single extraction flow.
 */
final class ArchiveExtractionState {
  final ArchiveExtractionInput input;
  final ArchiveElementRequest elementRequest;
  final MutableBoolean gotElement;
  final boolean throwAtExit;
  final long expectedSize;

  /**
   * Creates a new extraction state bundle.
   *
   * @param input source inputs for the archive extraction
   * @param elementRequest requested element and callback details
   * @param gotElement mutable flag that tracks when the requested element is delivered
   * @param throwAtExit whether extraction should trigger a restart after completion
   * @param expectedSize expected archive size for formats that require it
   */
  ArchiveExtractionState(
      ArchiveExtractionInput input,
      ArchiveElementRequest elementRequest,
      MutableBoolean gotElement,
      boolean throwAtExit,
      long expectedSize) {
    this.input = input;
    this.elementRequest = elementRequest;
    this.gotElement = gotElement;
    this.throwAtExit = throwAtExit;
    this.expectedSize = expectedSize;
  }
}

package network.crypta.client.async;

import java.io.DataInputStream;

/**
 * Holds the results of initializing splitfile segment and cross-segment storage.
 *
 * <p>This package-private container groups the arrays produced during segment setup with the
 * remainder of the settings stream, if any. It is returned by {@link
 * SplitFileFetcherSegmentsBuilder} to convey the initialized segment storage objects together with
 * any cross-segment helpers and the stream position that follows them. Callers typically unpack the
 * fields immediately and do not retain the instance beyond construction of {@link
 * SplitFileFetcherStorage} state.
 *
 * <p>The instance is immutable but references mutable arrays and a stream, so it should be treated
 * as a transient handoff object. The arrays are expected to be fully populated by the builder; when
 * cross-segment storage is not present, {@code crossSegments} may be {@code null}.
 *
 * <ul>
 *   <li>Provides segment storage objects ready for scheduling.
 *   <li>Optionally supplies cross-segment storage helpers when present in the format.
 *   <li>Exposes the remaining stream for additional resume parsing.
 * </ul>
 *
 * @see SplitFileFetcherSegmentsBuilder
 */
final class SplitFileFetcherSegmentsInit {
  /** Segment storage instances constructed for the splitfile; never {@code null}. */
  final SplitFileFetcherSegmentStorage[] segments;

  /** Cross-segment storage instances or {@code null} when the format omits them. */
  final SplitFileFetcherCrossSegmentStorage[] crossSegments;

  /** Stream positioned after segment data, or {@code null} when none remains. */
  final DataInputStream remainingStream;

  /**
   * Creates a new result holder for segment initialization.
   *
   * @param segments segment storage array populated by the builder; must not be {@code null}.
   * @param crossSegments cross-segment storage array or {@code null} when absent.
   * @param remainingStream stream positioned after segment parsing; may be {@code null}.
   */
  SplitFileFetcherSegmentsInit(
      SplitFileFetcherSegmentStorage[] segments,
      SplitFileFetcherCrossSegmentStorage[] crossSegments,
      DataInputStream remainingStream) {
    this.segments = segments;
    this.crossSegments = crossSegments;
    this.remainingStream = remainingStream;
  }
}

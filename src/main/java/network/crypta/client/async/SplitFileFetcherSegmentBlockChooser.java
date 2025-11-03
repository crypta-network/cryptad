package network.crypta.client.async;

import java.io.IOException;
import java.util.Random;
import network.crypta.node.KeysFetchingLocally;

/**
 * Chooses and validates fetch attempts for blocks within a single split‑file segment.
 *
 * <p>This chooser builds on {@link CooldownBlockChooser} by adding per‑segment eligibility rules
 * specific to fetching. In addition to the inherited retry accounting and cooldown windows, it can
 * (optionally) ignore one designated block index and consults {@link KeysFetchingLocally} to avoid
 * selecting blocks that the client is already fetching elsewhere. The designated ignored index is
 * typically used to defer a special trailing block (for example, a partially padded last data
 * block) until other work completes or additional context is available.
 *
 * <p>Instances are stateful. The selection path in the parent class is synchronized and invokes the
 * {@link #checkValid(int)} hook to filter candidates for the current attempt. Callers obtain the
 * next eligible block index by invoking {@code chooseKey()} on this chooser; a return value of
 * {@code -1} indicates a global cooldown is in effect. No I/O is performed during construction, but
 * validating a candidate may read the segment's key list from disk.
 *
 * <ul>
 *   <li>Cooldown: inherits per‑block cooldown after repeated non‑fatal failures.
 *   <li>De‑duplication: skips blocks already tracked by {@code KeysFetchingLocally}.
 *   <li>Ignored index: optionally excludes one specific block from selection.
 * </ul>
 *
 * @see CooldownBlockChooser
 * @see SplitFileFetcherSegmentStorage
 * @see KeysFetchingLocally
 */
public class SplitFileFetcherSegmentBlockChooser extends CooldownBlockChooser {

  /**
   * Creates a chooser for a fetcher segment, configuring retry and cooldown policies.
   *
   * <p>The {@code blocks} argument defines the number of candidate block indices tracked by this
   * chooser. Cooldown behavior and retry limits are inherited from {@link CooldownBlockChooser}.
   * When {@code ignoreLastBlock} is non‑negative, that zero‑based index is excluded from
   * eligibility checks performed by {@link #checkValid(int)}.
   *
   * @param blocks total number of blocks managed by this chooser; valid indices are {@code [0,
   *     blocks)} and the value must be non‑negative and consistent with the segment.
   * @param random randomness source used by the base selection logic to break ties among eligible
   *     candidates fairly; must not be {@code null}.
   * @param maxRetries maximum number of non‑fatal failures allowed per block before it is
   *     considered exhausted; use {@code -1} to allow unlimited retries.
   * @param cooldownTries number of attempts between cooldowns; when non‑zero, every {@code
   *     cooldownTries}th attempt schedules a temporary cooldown window for a block.
   * @param cooldownTime cooldown duration in milliseconds added to {@link
   *     System#currentTimeMillis()} to compute per‑block wake‑up times.
   * @param segment backing segment storage that provides key material and overall segment context;
   *     must not be {@code null}.
   * @param keysFetching coordinator tracking keys being fetched locally so duplicate work can be
   *     avoided; used to filter out in‑flight duplicates.
   * @param ignoreLastBlock zero‑based block index to exclude from selection, or {@code -1} to
   *     disable the exclusion and consider all indices.
   */
  public SplitFileFetcherSegmentBlockChooser(
      int blocks,
      Random random,
      int maxRetries,
      int cooldownTries,
      long cooldownTime,
      SplitFileFetcherSegmentStorage segment,
      KeysFetchingLocally keysFetching,
      int ignoreLastBlock) {
    super(blocks, random, maxRetries, cooldownTries, cooldownTime);
    this.segment = segment;
    this.keysFetching = keysFetching;
    this.ignoreLastBlock = ignoreLastBlock;
  }

  private final SplitFileFetcherSegmentStorage segment;
  private final KeysFetchingLocally keysFetching;
  private final int ignoreLastBlock;

  /**
   * Determines whether the given block index is currently eligible for a fetch attempt.
   *
   * <p>This override first applies the base validity checks, including retry budget and cooldown
   * windows. It then excludes a designated index when {@code ignoreLastBlock} is set, and finally
   * consults the {@link KeysFetchingLocally} coordinator to avoid fetching a key that is already in
   * flight. If reading the segment's key list fails with an {@link IOException}, the segment is
   * scheduled to fail asynchronously and the candidate is rejected for this selection cycle.
   *
   * @param chosen zero‑based block index to validate for selection; must lie within the configured
   *     range for this chooser instance.
   * @return {@code true} when the index passes base checks, is not the ignored index, and is not
   *     already being fetched locally; {@code false} otherwise.
   */
  @Override
  protected boolean checkValid(int chosen) {
    if (!super.checkValid(chosen)) return false;
    if (chosen == ignoreLastBlock) return false;
    try {
      SplitFileSegmentKeys keys = segment.getSegmentKeys();
      return !keysFetching.hasKey(
          keys.getNodeKey(chosen, null, false), segment.parent.fetcher.getSendableGet());
    } catch (final IOException e) {
      segment.parent.jobRunner.queueNormalOrDrop(
          context -> {
            segment.parent.failOnDiskError(e);
            return true;
          });
      return false;
    }
  }
}

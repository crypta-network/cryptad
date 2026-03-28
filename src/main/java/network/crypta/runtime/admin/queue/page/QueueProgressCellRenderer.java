package network.crypta.runtime.admin.queue.page;

import java.util.Objects;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * Renders the legacy queue progress cell without depending on HTTP-layer helpers.
 *
 * <p>The implementation intentionally preserves the established queue-page HTML structure and
 * localization keys, so the extracted queue-page seam remains a mechanical decoupling step. Callers
 * hand the renderer a small immutable context plus the current splitfile counters, and the renderer
 * returns the exact queue-cell subtree that can be embedded in the legacy table output.
 *
 * <p>The class is deliberately stateless. All operator-visible wording still comes from the
 * existing {@code QueueToadlet.*} localization keys, and the progress-bar structure matches the
 * legacy page so this seam extraction does not become an HTML redesign.
 */
public final class QueueProgressCellRenderer {
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_STYLE = "style";
  private static final String ATTR_TITLE = "title";
  private static final String CSS_WIDTH_PREFIX = "width: ";
  private static final String UNKNOWN = "unknown";
  private static final String QUEUE_TOADLET_PREFIX = "QueueToadlet.";

  private QueueProgressCellRenderer() {}

  /**
   * Creates the queue progress cell for the provided context and counters.
   *
   * <p>The renderer first handles the early states that should display plain text instead of a
   * progress bar, such as requests that have not started or uploads waiting for compression. Once a
   * row is eligible for numeric progress, the method computes the same percentages and titles that
   * the legacy HTTP helper produced and returns a detached {@code <td>} subtree ready for insertion
   * into the queue table.
   *
   * @param context rendering context that describes the request state outside the numeric counters
   * @param counts splitfile progress counters captured for the request at this render instant
   * @return HTML node representing the queue progress cell with legacy-compatible structure
   */
  public static HTMLNode createProgressCell(
      QueueProgressCellContext context, SplitfileProgressCounts counts) {
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(counts, "counts");

    HTMLNode progressCell = new HTMLNode("td", ATTR_CLASS, "request-progress");
    if (handleEarlyProgressMessages(context, progressCell)) {
      return progressCell;
    }

    int adjustedTotal =
        adjustTotal(context.advancedMode(), counts.minSuccessfulBlocks(), counts.totalBlocks());

    if (counts.succeedBlocks() < 0 || adjustedTotal <= 0) {
      progressCell.addChild("span", ATTR_CLASS, "progress_fraction_unknown", l10n(UNKNOWN));
    } else {
      addProgressBar(
          progressCell, counts, adjustedTotal, counts.finalizedTotal(), context.upload());
    }
    return progressCell;
  }

  private static boolean handleEarlyProgressMessages(
      QueueProgressCellContext context, HTMLNode progressCell) {
    if (!context.started()) {
      progressCell.addChild("#", l10n("starting"));
      return true;
    }
    if (context.compressing() == QueueCompressionState.WAITING && context.advancedMode()) {
      progressCell.addChild("#", l10n("awaitingCompression"));
      return true;
    }
    if (context.compressing() != QueueCompressionState.WORKING) {
      progressCell.addChild("#", l10n("compressing"));
      return true;
    }
    return false;
  }

  private static int adjustTotal(boolean advancedMode, int min, int total) {
    return !advancedMode || total < min ? min : total;
  }

  private static void addProgressBar(
      HTMLNode progressCell,
      SplitfileProgressCounts progressCounts,
      int adjustedTotal,
      boolean finalized,
      boolean upload) {
    int fetchedPercent = (int) (progressCounts.succeedBlocks() / (double) adjustedTotal * 100);
    int failedPercent = (int) (progressCounts.failedBlocks() / (double) adjustedTotal * 100);
    int fatallyFailedPercent =
        (int) (progressCounts.fatallyFailedBlocks() / (double) adjustedTotal * 100);
    int minPercent = (int) (progressCounts.minSuccessfulBlocks() / (double) adjustedTotal * 100);
    HTMLNode progressBar = progressCell.addChild("div", ATTR_CLASS, "progressbar");
    progressBar.addChild(
        "div",
        new String[] {ATTR_CLASS, ATTR_STYLE},
        new String[] {"progressbar-done", CSS_WIDTH_PREFIX + fetchedPercent + "%;"});

    if (progressCounts.failedBlocks() > 0) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {"progressbar-failed", CSS_WIDTH_PREFIX + failedPercent + "%;"});
    }
    if (progressCounts.fatallyFailedBlocks() > 0) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {"progressbar-failed2", CSS_WIDTH_PREFIX + fatallyFailedPercent + "%;"});
    }
    if ((progressCounts.succeedBlocks()
            + progressCounts.failedBlocks()
            + progressCounts.fatallyFailedBlocks())
        < progressCounts.minSuccessfulBlocks()) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_STYLE},
          new String[] {
            "progressbar-min", CSS_WIDTH_PREFIX + (minPercent - fetchedPercent) + "%;"
          });
    }

    String prefix =
        '('
            + Integer.toString(progressCounts.succeedBlocks())
            + "/ "
            + progressCounts.minSuccessfulBlocks()
            + "): ";
    addProgressTitle(
        progressBar,
        progressCounts.succeedBlocks(),
        progressCounts.minSuccessfulBlocks(),
        finalized,
        upload,
        prefix);
  }

  private static void addProgressTitle(
      HTMLNode progressBar,
      int fetched,
      int min,
      boolean finalized,
      boolean upload,
      String prefix) {
    double percent = min == 0 ? 0.0 : (fetched / (double) min) * 100.0;
    double roundedPercent = Math.round(percent * 10.0) / 10.0;
    String percentText = roundedPercent + "%";
    if (finalized) {
      progressBar.addChild(
          "div",
          new String[] {ATTR_CLASS, ATTR_TITLE},
          new String[] {"progress_fraction_finalized", prefix + l10n("progressbarAccurate")},
          percentText);
      return;
    }
    String text = fetched + " (" + percentText + "??)";
    progressBar.addChild(
        "div",
        new String[] {ATTR_CLASS, ATTR_TITLE},
        new String[] {
          "progress_fraction_not_finalized",
          prefix
              + NodeL10n.getBase()
                  .getString(
                      upload
                          ? QUEUE_TOADLET_PREFIX + "uploadProgressbarNotAccurate"
                          : QUEUE_TOADLET_PREFIX + "progressbarNotAccurate")
        },
        text);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key);
  }
}

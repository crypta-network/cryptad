package network.crypta.runtime.admin.queue.page;

import java.util.List;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class QueueProgressCellRendererTest {
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_STYLE = "style";
  private static final String ATTR_TITLE = "title";

  @Test
  void createProgressCell_whenRequestNotStarted_rendersStartingMessage() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(false, false, QueueCompressionState.WORKING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, 0, 0, 0, 5, false));

    // Assert
    assertEquals("td", progressCell.getName());
    assertEquals("request-progress", progressCell.getAttribute(ATTR_CLASS));
    assertTextChild(progressCell, l10n("starting"));
  }

  @Test
  void createProgressCell_whenAdvancedModeAwaitingCompression_rendersAwaitingCompressionMessage() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(true, true, QueueCompressionState.WAITING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, 0, 0, 0, 5, false));

    // Assert
    assertTextChild(progressCell, l10n("awaitingCompression"));
  }

  @Test
  void createProgressCell_whenCompressionInProgress_rendersCompressingMessage() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(false, true, QueueCompressionState.COMPRESSING, true);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, 0, 0, 0, 5, false));

    // Assert
    assertTextChild(progressCell, l10n("compressing"));
  }

  @Test
  void createProgressCell_whenSucceedBlocksNegative_rendersUnknownProgress() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(true, true, QueueCompressionState.WORKING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, -1, 0, 0, 5, false));

    // Assert
    assertUnknownProgress(progressCell);
  }

  @Test
  void createProgressCell_whenAdjustedTotalNonPositive_rendersUnknownProgress() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(true, true, QueueCompressionState.WORKING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(0, 0, 0, 0, 0, false));

    // Assert
    assertUnknownProgress(progressCell);
  }

  @Test
  void createProgressCell_whenFinalizedWithFailures_rendersAccurateProgressBar() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(true, true, QueueCompressionState.WORKING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, 5, 2, 1, 9, true));

    // Assert
    HTMLNode progressBar = getSingleChild(progressCell);
    assertEquals("div", progressBar.getName());
    assertEquals("progressbar", progressBar.getAttribute(ATTR_CLASS));
    assertEquals(
        "width: 50%;", getChildWithClass(progressBar, "progressbar-done").getAttribute(ATTR_STYLE));
    getChildWithClass(progressBar, "progressbar-failed");
    getChildWithClass(progressBar, "progressbar-failed2");
    assertEquals(
        "width: 40%;", getChildWithClass(progressBar, "progressbar-min").getAttribute(ATTR_STYLE));

    HTMLNode fraction = getChildWithClass(progressBar, "progress_fraction_finalized");
    assertEquals("(5/ 9): " + l10n("progressbarAccurate"), fraction.getAttribute(ATTR_TITLE));
    assertTextChild(fraction, "55.6%");
  }

  @Test
  void createProgressCell_whenDownloadNotFinalized_usesMinimumBlocksForPercentAndDownloadTitle() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(false, true, QueueCompressionState.WORKING, false);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(10, 3, 0, 0, 6, false));

    // Assert
    HTMLNode progressBar = getSingleChild(progressCell);
    assertEquals(
        "width: 50%;", getChildWithClass(progressBar, "progressbar-done").getAttribute(ATTR_STYLE));
    getChildWithClass(progressBar, "progressbar-min");
    HTMLNode fraction = getChildWithClass(progressBar, "progress_fraction_not_finalized");
    assertEquals("(3/ 6): " + l10n("progressbarNotAccurate"), fraction.getAttribute(ATTR_TITLE));
    assertTextChild(fraction, "3 (50.0%??)");
  }

  @Test
  void createProgressCell_whenUploadNotFinalized_usesUploadSpecificInaccurateTitle() {
    // Arrange
    QueueProgressCellContext context =
        new QueueProgressCellContext(true, true, QueueCompressionState.WORKING, true);

    // Act
    HTMLNode progressCell =
        QueueProgressCellRenderer.createProgressCell(context, counts(4, 3, 0, 0, 6, false));

    // Assert
    HTMLNode progressBar = getSingleChild(progressCell);
    assertEquals(
        "width: 50%;", getChildWithClass(progressBar, "progressbar-done").getAttribute(ATTR_STYLE));
    getChildWithClass(progressBar, "progressbar-min");
    HTMLNode fraction = getChildWithClass(progressBar, "progress_fraction_not_finalized");
    assertEquals(
        "(3/ 6): " + l10n("uploadProgressbarNotAccurate"), fraction.getAttribute(ATTR_TITLE));
    assertTextChild(fraction, "3 (50.0%??)");
  }

  @Test
  void constructor_whenCompressionStateNull_throwsNullPointerException() {
    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> new QueueProgressCellContext(true, true, null, false));
  }

  private static SplitfileProgressCounts counts(
      int total, int succeed, int failed, int fatal, int minSuccessful, boolean finalized) {
    return new SplitfileProgressCounts(total, succeed, failed, fatal, minSuccessful, 0, finalized);
  }

  private static void assertUnknownProgress(HTMLNode progressCell) {
    HTMLNode unknown = getSingleChild(progressCell);
    assertEquals("span", unknown.getName());
    assertEquals("progress_fraction_unknown", unknown.getAttribute(ATTR_CLASS));
    assertTextChild(unknown, l10n("unknown"));
  }

  private static void assertTextChild(HTMLNode parent, String expectedContent) {
    HTMLNode child = getSingleChild(parent);
    assertEquals("#", child.getName());
    assertEquals(expectedContent, child.getContent());
  }

  private static HTMLNode getSingleChild(HTMLNode parent) {
    List<HTMLNode> children = parent.getChildren();
    assertEquals(1, children.size(), "Expected exactly one child node");
    return children.getFirst();
  }

  private static HTMLNode getChildWithClass(HTMLNode parent, String className) {
    HTMLNode match = null;
    for (HTMLNode child : parent.getChildren()) {
      if (className.equals(child.getAttribute(ATTR_CLASS))) {
        match = child;
        break;
      }
    }
    assertNotNull(match, "Expected child with class " + className);
    return match;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("QueueToadlet." + key);
  }
}

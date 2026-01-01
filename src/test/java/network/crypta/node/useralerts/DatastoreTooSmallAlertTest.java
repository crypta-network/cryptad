package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

import java.nio.file.Path;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.Version;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "PointlessArithmeticExpression"})
// method names follow Arrange-Act-Assert readability pattern
@ExtendWith(MockitoExtension.class)
class DatastoreTooSmallAlertTest {

  private static final long GIB = 1024L * 1024L * 1024L;
  private static final long MIB = 1024L * 1024L;

  @TempDir Path tempDir;

  @Mock NodeClientCore core;
  @Mock Node node;

  private SubConfig nodeConfig;

  @BeforeEach
  void setUp() {
    PersistentConfig config = new PersistentConfig(null);
    nodeConfig = config.createSubConfig("node");

    lenient().when(core.getNode()).thenReturn(node);
    lenient().when(node.getConfig()).thenReturn(config);
    lenient().when(node.getStoreDir()).thenReturn(tempDir.toFile());
  }

  private void registerSizeOptions(long storeSizeBytes, long clientCacheBytes, long slashdotBytes) {
    // Register the three size options (as sizes)
    nodeConfig.register("storeSize", storeSizeBytes, 0, false, true, "", "", null, true);
    nodeConfig.register("clientCacheSize", clientCacheBytes, 0, false, true, "", "", null, true);
    nodeConfig.register("slashdotCacheSize", slashdotBytes, 0, false, true, "", "", null, true);

    // Also required by DATASTORE_SIZE._setDatastoreSize but not directly used here; harmless to
    // set.
    nodeConfig.register("inputBandwidthLimit", 0, 0, false, true, "", "", null /* IntCallback */);
    nodeConfig.register("outputBandwidthLimit", 0, 0, false, true, "", "", null /* IntCallback */);
    nodeConfig.register("slashdotCacheLifetime", 0L, 0, false, true, "", "", null, false);
  }

  private void registerDismissed(String initial) {
    int initVal;
    try {
      initVal = Integer.parseInt(initial);
    } catch (NumberFormatException _) {
      initVal = 0;
    }
    nodeConfig.register(
        "datastoreTooSmallDismissed", initVal, 0, false, true, "", "", null /* IntCallback */);
  }

  private static long expectedCurrentGiB(long store, long client, long slashdot) {
    long total = store + client + slashdot;
    total = (long) ((double) total * 1.036d);
    return (total + 512L * 1024L * 1024L) / GIB;
  }

  @Test
  void getShortText_whenCalled_matchesTitle() {
    registerSizeOptions(1 * GIB, 512 * MIB, 256 * MIB);
    registerDismissed("0");

    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);

    assertEquals(alert.getTitle(), alert.getShortText(), "Short text should equal title");
  }

  @Test
  void getText_whenSizesConfigured_includesLocalizedCurrentAndAvailable() {
    registerSizeOptions(1 * GIB, 512 * MIB, 256 * MIB);
    registerDismissed("0");

    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    String text = alert.getText();

    // Current size should be computed deterministically from configured sizes
    long expectedCurrent = expectedCurrentGiB(1 * GIB, 512 * MIB, 256 * MIB);
    String expectedCurrentLine =
        network.crypta.l10n.NodeL10n.getBase()
            .getString("DataStoreTooSmallAlert.current", "size", expectedCurrent + " GiB");
    assertTrue(
        text.contains(expectedCurrentLine),
        () ->
            "Text should include current size line with GiB. Expected snippet: '"
                + expectedCurrentLine
                + "' Actual: "
                + text);

    // Available line should be present; we don't assert the exact number to avoid env coupling
    assertTrue(
        text.contains("Total available disk space: "),
        "Text should include the available size line");
  }

  @Test
  void getHTMLText_whenCalled_containsExpectedStructureAndLink() {
    registerSizeOptions(2 * GIB, 256 * MIB, 128 * MIB);
    registerDismissed("0");

    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    HTMLNode html = alert.getHTMLText();
    String rendered = html.generate();

    long expectedCurrent = expectedCurrentGiB(2 * GIB, 256 * MIB, 128 * MIB);
    assertTrue(
        rendered.contains("Your current datastore size: " + expectedCurrent + " GiB"),
        "HTML should include current size line");
    assertTrue(
        rendered.contains("Total available disk space: "),
        "HTML should include available size line");
    assertTrue(
        rendered.contains("/wizard/?step=DATASTORE_SIZE") && rendered.contains("singlestep=true"),
        "HTML should include link to datastore size wizard");
    assertTrue(
        rendered.contains("Go to datastore size configuration"),
        "HTML should include the submit link text");
  }

  @Test
  void getPriorityClass_whenCalled_isWarning() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());
  }

  @Test
  void isValid_whenDismissedForCurrentBuild_returnsFalseRegardlessOfSizes() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed(Integer.toString(Version.currentBuildNumber()));
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertFalse(alert.isValid(), "Alert must be invalid when dismissed for current build");
  }

  @Test
  void isValid_whenCurrentSizeVeryLarge_returnsFalse() {
    // Ensure current size >= 25 GiB so it cannot be below the warning threshold (max 25 GiB)
    registerSizeOptions(30 * GIB, 1 * GIB, 1 * GIB);
    registerDismissed("0");

    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertFalse(alert.isValid(), "Large current size should not trigger the alert");
  }

  @Test
  void onDismiss_whenCalled_persistsCurrentBuildNumberInConfig() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);

    alert.onDismiss();

    int stored = nodeConfig.getInt("datastoreTooSmallDismissed");
    assertEquals(Version.currentBuildNumber(), stored);
  }

  @Test
  void dismissButtonText_whenCalled_isHideFromL10n() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertEquals("Hide", alert.dismissButtonText());
  }

  @Test
  void anchor_whenCalled_isStable() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertEquals("datastore-too-small", alert.anchor());
  }

  @Test
  void isEventNotification_whenCalled_isFalse() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertFalse(alert.isEventNotification());
  }

  @Test
  void getUpdatedTime_whenCalled_returnsRecentTimestamp() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    long before = System.currentTimeMillis();
    long ts = alert.getUpdatedTime();
    long after = System.currentTimeMillis();
    assertTrue(ts >= before && ts <= after, "Updated time should be within invocation window");
  }

  @Test
  void getFCPMessage_whenCalled_containsTitleShortTextAndTime() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);

    FCPMessage msg = alert.getFCPMessage();
    assertInstanceOf(FeedMessage.class, msg, "Expected FeedMessage implementation");

    SimpleFieldSet fs = msg.getFieldSet();
    assertEquals(alert.getTitle(), fs.get("Header"));
    assertEquals(alert.getShortText(), fs.get("ShortText"));
    int pc = Integer.parseInt(fs.get("PriorityClass"));
    assertEquals(UserAlert.WARNING, pc);

    long updated = Long.parseLong(fs.get("UpdatedTime"));
    long now = System.currentTimeMillis();
    // Within a reasonable bound of 'now'
    assertTrue(updated <= now && updated > now - 10_000L, "Updated time should be recent");
  }

  @Test
  void userCanDismiss_whenCalled_isTrueAndUnregisterOnDismiss() {
    registerSizeOptions(1 * GIB, 0, 0);
    registerDismissed("0");
    DatastoreTooSmallAlert alert = new DatastoreTooSmallAlert(core);
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.shouldUnregisterOnDismiss());
  }
}

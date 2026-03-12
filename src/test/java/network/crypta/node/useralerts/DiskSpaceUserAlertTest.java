package network.crypta.node.useralerts;

import java.io.File;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class DiskSpaceUserAlertTest {

  // Helper File that returns a fixed usable space regardless of the real filesystem.
  private static final class FakeFile extends File {
    private final long usableSpace;

    FakeFile(String pathname, long usableSpace) {
      super(pathname);
      this.usableSpace = usableSpace;
    }

    @Override
    public long getUsableSpace() {
      return usableSpace;
    }

    @Override
    public boolean equals(Object obj) {
      return super.equals(obj);
    }

    @Override
    public int hashCode() {
      return super.hashCode();
    }
  }

  private static DiskSpaceUserAlert newAlert(
      long shortLimit, long longLimit, File tempDir, File persistentDirOrNull) {
    NodeClientCore core = mock(NodeClientCore.class);
    lenient().when(core.getMinDiskFreeShortTerm()).thenReturn(shortLimit);
    lenient().when(core.getMinDiskFreeLongTerm()).thenReturn(longLimit);

    lenient().when(core.getTempDir()).thenReturn(tempDir);

    if (persistentDirOrNull == null) {
      lenient().when(core.getPersistentTempDir()).thenReturn(null);
    } else {
      lenient().when(core.getPersistentTempDir()).thenReturn(persistentDirOrNull);
    }
    return new DiskSpaceUserAlert(core);
  }

  @Test
  void evaluate_whenTempBelowShortTerm_returnsTRANSIENT_andTextMentionsTemp() {
    long shortLimit = 1_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit - 1); // below short-term
    File persistent = new FakeFile("/tmp/persistent-space", longLimit + 1);
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, persistent);

    // Act
    DiskSpaceUserAlert.Status status = alert.evaluate();
    String text = alert.getText();

    // Assert
    assertEquals(DiskSpaceUserAlert.Status.TRANSIENT, status);
    assertTrue(text.contains(temp.toString()));
    assertTrue(text.contains(DiskSpaceUserAlert.Status.TRANSIENT.getExplanation()));
    assertTrue(text.contains(NodeL10n.getBase().getString("DiskSpaceUserAlert.action")));
  }

  @Test
  void
      evaluate_whenPersistentBelowShortTerm_returnsPERSISTENT_COMPLETION_andTextMentionsPersistent() {
    long shortLimit = 2_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit); // meets short-term
    File persistent = new FakeFile("/tmp/persistent-space", shortLimit - 1); // below short-term
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, persistent);

    DiskSpaceUserAlert.Status status = alert.evaluate();
    String text = alert.getText();

    assertEquals(DiskSpaceUserAlert.Status.PERSISTENT_COMPLETION, status);
    assertTrue(text.contains(persistent.toString()));
    assertTrue(text.contains(DiskSpaceUserAlert.Status.PERSISTENT_COMPLETION.getExplanation()));
  }

  @Test
  void evaluate_whenPersistentBelowLongTerm_only_returnsPERSISTENT_andTextMentionsPersistent() {
    long shortLimit = 2_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit + 1); // above short-term
    File persistent = new FakeFile("/tmp/persistent-space", longLimit - 1); // below long-term
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, persistent);

    DiskSpaceUserAlert.Status status = alert.evaluate();
    String text = alert.getText();

    assertEquals(DiskSpaceUserAlert.Status.PERSISTENT, status);
    assertTrue(text.contains(persistent.toString()));
    assertTrue(text.contains(DiskSpaceUserAlert.Status.PERSISTENT.getExplanation()));
  }

  @Test
  void evaluate_whenAllAboveThresholds_returnsOK_andInvalid() {
    long shortLimit = 1_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit + 5);
    File persistent = new FakeFile("/tmp/persistent-space", longLimit + 5);
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, persistent);

    assertEquals(DiskSpaceUserAlert.Status.OK, alert.evaluate());
    assertFalse(alert.isValid());
  }

  @Test
  void evaluate_whenNoPersistentGenerator_usesTempOnly_andOK() {
    long shortLimit = 1_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit + 1);
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, null);

    assertEquals(DiskSpaceUserAlert.Status.OK, alert.evaluate());
  }

  @Test
  void getHTMLText_returnsTextNodeWithSameContent() {
    long shortLimit = 2_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit - 1); // trigger TRANSIENT
    File persistent = new FakeFile("/tmp/persistent-space", longLimit + 1);
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, persistent);

    String text = alert.getText();
    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals(text, html.generateChildren());
  }

  @Test
  void basic_properties_areConsistent() {
    DiskSpaceUserAlert alert = newAlert(1, 2, new FakeFile("/t", 0), new FakeFile("/p", 0));

    assertTrue(alert.userCanDismiss());
    assertEquals(alert.getTitle(), alert.getShortText());
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());
    assertEquals("not-enough-disk-space", alert.anchor());
    assertFalse(alert.isEventNotification());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
  }

  @Test
  void isValid_boolean_noop_doesNotChangeValidity() {
    // Arrange a non-OK status so validity is true
    long shortLimit = 5;
    DiskSpaceUserAlert alert = newAlert(shortLimit, shortLimit + 10, new FakeFile("/t", 0), null);
    assertTrue(alert.isValid());

    // Act: toggle validity flag (no-op per implementation)
    alert.isValid(false);

    // Assert: still valid because status did not change
    assertTrue(alert.isValid());
  }

  @Test
  void getFCPMessage_containsExpectedFields_andUpdatedTimeMatches() {
    long shortLimit = 2_000L;
    long longLimit = 10_000L;
    File temp = new FakeFile("/tmp/temp-space", shortLimit - 1); // TRANSIENT
    DiskSpaceUserAlert alert = newAlert(shortLimit, longLimit, temp, null);

    // Force evaluation to set updated time
    String text = alert.getText();
    long updated = alert.getUpdatedTime();
    assertTrue(updated > 0);

    FCPMessage msg = alert.getFCPMessage();
    assertInstanceOf(FeedMessage.class, msg);
    SimpleFieldSet fs = msg.getFieldSet();

    assertEquals(alert.getTitle(), fs.get("Header"));
    assertEquals(alert.getShortText(), fs.get("ShortText"));
    assertEquals(alert.getPriorityClass(), fs.getShort("PriorityClass", (short) -1));
    assertEquals(updated, fs.getLong("UpdatedTime", -1L));

    int textLen = text.getBytes(UTF_8).length;
    assertEquals(textLen, fs.getInt("TextLength", -1));
    assertEquals(textLen, fs.getInt("DataLength", -1));
  }

  @Test
  void isValid_whenCoreThrowsDuringEvaluate_returnsFalseAndUpdatedTimeStaysZero() {
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getMinDiskFreeShortTerm()).thenReturn(100L);
    when(core.getMinDiskFreeLongTerm()).thenReturn(200L);
    // Cause evaluate() to throw via getTempDir()
    when(core.getTempDir()).thenThrow(new RuntimeException("boom"));

    DiskSpaceUserAlert alert = new DiskSpaceUserAlert(core);

    assertFalse(alert.isValid()); // Implementation catches and treats as OK
    assertEquals(0L, alert.getUpdatedTime()); // not updated on failure path

    // getText() may still throw because getWhere(status) re-enters core; assert that behavior
    assertThrows(Exception.class, alert::getText);
  }
}

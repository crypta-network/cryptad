package network.crypta.runtime.alerts;

import java.io.StringReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.L10nTestUtils;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // allow descriptive test method names
class UserAlertManagerTest {

  private static final XPath X_PATH = XPathFactory.newInstance().newXPath();

  @Mock private NodeClientCore nodeClientCore;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private ClientContext clientContext;
  @Mock private PriorityAwareExecutor executor;

  private UserAlertManager userAlertManager;
  private BaseL10n originalBase;

  @BeforeEach
  void setUp() {
    originalBase = NodeL10n.getBase();
    L10nTestUtils.useTestTranslation();
    lenient().when(nodeClientCore.getNode()).thenReturn(node);
    lenient().when(node.network().darknetPubKeyHash()).thenReturn(new byte[] {1, 2, 3, 4});
    lenient().when(nodeClientCore.getClientContext()).thenReturn(clientContext);
    lenient().when(clientContext.getMainExecutor()).thenReturn(executor);
    lenient().when(nodeClientCore.getFormPassword()).thenReturn("form-password");
    lenient()
        .doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());
    lenient()
        .doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));
    userAlertManager = new UserAlertManager(nodeClientCore);
  }

  @AfterEach
  void tearDown() throws ReflectiveOperationException {
    installBase(originalBase);
  }

  @Test
  void getAtom_whenGenerated_expectFeedMetadataPresent() throws Exception {
    // Arrange
    String atom = userAlertManager.getAtom("http://test");

    // Act
    Document atomXml = parseAtomXml(atom);

    // Assert
    assertEquals("UserAlertManager.feedTitle", X_PATH.evaluate("/feed/title", atomXml));
    assertEquals("http://test/feed/", X_PATH.evaluate("/feed/link[@rel='self']/@href", atomXml));
    assertEquals("http://test", X_PATH.evaluate("/feed/link[count(@rel)=0]/@href", atomXml));
    assertTrue(
        X_PATH
            .evaluate("/feed/updated", atomXml)
            .matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}[+-]\\d{2}:\\d{2}"));
    assertEquals("urn:node:AQIDBA", X_PATH.evaluate("/feed/id", atomXml));
    assertEquals("/favicon.ico", X_PATH.evaluate("/feed/logo", atomXml));
  }

  @Test
  void getAtom_whenAlertsPresent_expectEntriesMatchAlerts() throws Exception {
    // Arrange
    TestAlert firstAlert =
        new TestAlert(
            true,
            "Alert 1",
            "Text 1",
            "Short 1",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "anchor-1");
    TestAlert secondAlert =
        new TestAlert(
            true,
            "Alert 2",
            "Text 2",
            "Short 2",
            UserAlert.ERROR,
            true,
            true,
            false,
            2_000L,
            "anchor-2");
    userAlertManager.register(secondAlert);
    userAlertManager.register(firstAlert);

    // Act
    Document atomXml = parseAtomXml(userAlertManager.getAtom("http://test"));
    List<EntrySnapshot> entries = getEntrySnapshots(atomXml);

    // Assert
    assertEquals(2, entries.size());
    assertTrue(entries.contains(entryFor(firstAlert)));
    assertTrue(entries.contains(entryFor(secondAlert)));
  }

  @Test
  void getAtom_whenAlertHasXmlCharacters_expectEscapedContent() throws Exception {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true,
            "Alert <",
            "Contains a <.",
            "Short <",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_234L,
            "alert-xml");
    userAlertManager.register(alert);

    // Act
    Document atomXml = parseAtomXml(userAlertManager.getAtom("http://test"));
    List<EntrySnapshot> entries = getEntrySnapshots(atomXml);

    // Assert
    assertEquals(1, entries.size());
    assertEquals(entryFor(alert), entries.getFirst());
  }

  @Test
  void getAtom_whenAlertInvalid_expectExcludedFromFeed() throws Exception {
    // Arrange
    TestAlert validAlert =
        new TestAlert(
            true,
            "Alert 1",
            "Text 1",
            "Short 1",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "valid");
    TestAlert invalidAlert =
        new TestAlert(
            true,
            "Alert 2",
            "Text 2",
            "Short 2",
            UserAlert.ERROR,
            false,
            true,
            false,
            2_000L,
            "invalid");
    userAlertManager.register(invalidAlert);
    userAlertManager.register(validAlert);

    // Act
    Document atomXml = parseAtomXml(userAlertManager.getAtom("http://test"));
    List<EntrySnapshot> entries = getEntrySnapshots(atomXml);

    // Assert
    assertEquals(1, entries.size());
    assertEquals(entryFor(validAlert), entries.getFirst());
  }

  @Test
  void getAtom_whenCustomAnchor_expectIdUsesAnchor() throws Exception {
    // Arrange
    TestAlert userAlert =
        new TestAlert(
            true,
            "Alert 1",
            "Text 1",
            "Short 1",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "test-anchor");
    userAlertManager.register(userAlert);

    // Act
    Document atomXml = parseAtomXml(userAlertManager.getAtom("http://test"));
    List<EntrySnapshot> entries = getEntrySnapshots(atomXml);

    // Assert
    assertEquals("urn:feed:test-anchor", entries.getFirst().id());
  }

  @Test
  void register_whenAlertDuplicate_expectSingleEntry() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true,
            "Title",
            "Text",
            "Short",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "duplicate");

    // Act
    userAlertManager.register(alert);
    userAlertManager.register(alert);

    // Assert
    UserAlert[] alerts = userAlertManager.getAlerts();
    assertArrayEquals(new UserAlert[] {alert}, alerts);
  }

  @Test
  void register_whenUserEventSameType_expectLatestEventKept() {
    // Arrange
    TestEvent firstEvent =
        new TestEvent(
            UserEvent.Type.GET_COMPLETED,
            true,
            "First",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            true,
            1_000L,
            "event-first");
    TestEvent secondEvent =
        new TestEvent(
            UserEvent.Type.GET_COMPLETED,
            true,
            "Second",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            true,
            2_000L,
            "event-second");

    // Act
    userAlertManager.register(firstEvent);
    userAlertManager.register(secondEvent);

    // Assert
    UserAlert[] alerts = userAlertManager.getAlerts();
    assertArrayEquals(new UserAlert[] {secondEvent}, alerts);
  }

  @Test
  void unregister_whenEventTypeUnregistersIndefinitely_expectFutureEventsIgnored() {
    // Arrange
    userAlertManager.unregister(UserEvent.Type.ANNOUNCER);
    TestEvent announcerEvent =
        new TestEvent(
            UserEvent.Type.ANNOUNCER,
            true,
            "Announce",
            "Text",
            "Short",
            UserAlert.MINOR,
            true,
            true,
            true,
            1_000L,
            "announcer");

    // Act
    userAlertManager.register(announcerEvent);

    // Assert
    assertEquals(0, userAlertManager.getAlerts().length);
  }

  @Test
  void unregister_whenAlertNull_expectNoInteraction() {
    // Arrange
    TestAlert existing =
        new TestAlert(
            true, "Title", "Text", "Short", UserAlert.WARNING, true, true, false, 1_000L, "keep");
    userAlertManager.register(existing);

    // Act
    userAlertManager.unregister((UserAlert) null);

    // Assert
    assertArrayEquals(new UserAlert[] {existing}, userAlertManager.getAlerts());
  }

  @Test
  void dismissAlert_whenUnregisterOnDismiss_expectRemovedAndDismissed() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true,
            "Title",
            "Text",
            "Short",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "dismiss-me");
    userAlertManager.register(alert);

    // Act
    userAlertManager.dismissAlert(alert.hashCode());

    // Assert
    assertTrue(alert.dismissed());
    assertEquals(0, userAlertManager.getAlerts().length);
  }

  @Test
  void dismissAlert_whenKeepRegistered_expectInvalidated() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true,
            "Title",
            "Text",
            "Short",
            UserAlert.ERROR,
            true,
            false,
            false,
            1_000L,
            "keep-registered");
    userAlertManager.register(alert);

    // Act
    userAlertManager.dismissAlert(alert.hashCode());

    // Assert
    assertFalse(alert.isValid());
    assertArrayEquals(new UserAlert[] {alert}, userAlertManager.getAlerts());
  }

  @Test
  void dismissAlert_whenUserCannotDismiss_expectIgnored() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            false,
            "Title",
            "Text",
            "Short",
            UserAlert.ERROR,
            true,
            true,
            false,
            1_000L,
            "cannot-dismiss");
    userAlertManager.register(alert);

    // Act
    userAlertManager.dismissAlert(alert.hashCode());

    // Assert
    assertTrue(alert.isValid());
    assertFalse(alert.dismissed());
  }

  @Test
  void getAlerts_whenSamePriorityWithEvent_expectEventSortedAfterNonEvent() {
    // Arrange
    TestAlert nonEvent =
        new TestAlert(
            true,
            "Non-event",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "non-event");
    TestAlert event =
        new TestAlert(
            true, "Event", "Text", "Short", UserAlert.WARNING, true, true, true, 2_000L, "event");
    userAlertManager.register(event);
    userAlertManager.register(nonEvent);

    // Act
    UserAlert[] alerts = userAlertManager.getAlerts();

    // Assert
    assertArrayEquals(new UserAlert[] {nonEvent, event}, alerts);
  }

  @Test
  void compare_whenSameClassDifferentUpdatedTime_expectNewestFirst() {
    // Arrange
    TestAlert older =
        new TestAlert(
            true, "Old", "Text", "Short", UserAlert.WARNING, true, true, false, 1_000L, "older");
    TestAlert newer =
        new TestAlert(
            true, "New", "Text", "Short", UserAlert.WARNING, true, true, false, 2_000L, "newer");

    // Act
    int result = userAlertManager.compare(newer, older);

    // Assert
    assertEquals(-1, result);
  }

  @Test
  void createAlerts_whenOnlyErrors_expectReturnsErrorsOnly() {
    // Arrange
    TestAlert errorAlert =
        new TestAlert(
            true, "Error", "Text", "Short", UserAlert.ERROR, true, true, false, 1_000L, "error");
    TestAlert warningAlert =
        new TestAlert(
            true,
            "Warning",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "warning");
    userAlertManager.register(errorAlert);
    userAlertManager.register(warningAlert);

    // Act
    HTMLNode alerts = userAlertManager.createAlerts(true);

    // Assert
    String html = alerts.generate();
    assertTrue(html.contains("Error"));
    assertFalse(html.contains("Warning"));
  }

  @Test
  void createAlerts_whenNoValidAlerts_expectEmptyNode() {
    // Arrange
    TestAlert invalidAlert =
        new TestAlert(
            true,
            "Invalid",
            "Text",
            "Short",
            UserAlert.ERROR,
            false,
            true,
            false,
            1_000L,
            "invalid");
    userAlertManager.register(invalidAlert);

    // Act
    HTMLNode alerts = userAlertManager.createAlerts(true);

    // Assert
    assertEquals("", alerts.generate());
  }

  @Test
  void renderAlert_whenUnknownLevel_expectErrorClass() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true, "Title", "Text", "Short", (short) 9, true, true, false, 1_000L, "unknown-level");

    // Act
    HTMLNode alertNode = userAlertManager.renderAlert(alert);

    // Assert
    assertTrue(alertNode.generate().contains("infobox infobox-error"));
  }

  @Test
  void renderDismissButton_whenDismissibleWithRedirect_expectHiddenFields() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            true,
            "Title",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "dismissable");

    // Act
    HTMLNode dismissNode = userAlertManager.renderDismissButton(alert, "/redirect");

    // Assert
    String html = dismissNode.generate();
    assertTrue(html.contains("formPassword"));
    assertTrue(html.contains("form-password"));
    assertTrue(html.contains("redirectToAfterDisable"));
  }

  @Test
  void renderDismissButton_whenNotDismissible_expectNoForm() {
    // Arrange
    TestAlert alert =
        new TestAlert(
            false,
            "Title",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "non-dismissable");

    // Act
    HTMLNode dismissNode = userAlertManager.renderDismissButton(alert, null);

    // Assert
    assertFalse(dismissNode.generate().contains("form"));
  }

  @Test
  void createSummary_whenOneLineWithOnlyErrors_expectNull() {
    // Arrange
    TestAlert errorAlert =
        new TestAlert(
            true, "Error", "Text", "Short", UserAlert.ERROR, true, true, false, 1_000L, "error");
    userAlertManager.register(errorAlert);

    // Act
    HTMLNode summary = userAlertManager.createSummary(true);

    // Assert
    assertNull(summary);
  }

  @Test
  void createSummary_whenWarningOneLine_expectWarningClass() {
    // Arrange
    TestAlert warningAlert =
        new TestAlert(
            true,
            "Warning",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "warning");
    userAlertManager.register(warningAlert);

    // Act
    HTMLNode summary = userAlertManager.createSummary(true);

    // Assert
    assertNotNull(summary);
    String html = summary.generate();
    assertTrue(html.contains("alerts-line contains-warning"));
    assertTrue(html.contains("messages-summary-box"));
  }

  @Test
  void createSummary_whenNoAlerts_expectEmptyNode() {
    // Arrange
    // No alerts registered

    // Act
    HTMLNode summary = userAlertManager.createSummary(false);

    // Assert
    assertEquals("", summary.generate());
  }

  @Test
  void dumpEvents_whenAnchorsMatch_expectDismissedAndRemoved() {
    // Arrange
    TestEvent event =
        new TestEvent(
            UserEvent.Type.PUT_COMPLETED,
            true,
            "Event",
            "Text",
            "Short",
            UserAlert.MINOR,
            true,
            true,
            true,
            1_000L,
            "event-anchor");
    TestAlert nonEvent =
        new TestAlert(
            true,
            "Alert",
            "Text",
            "Short",
            UserAlert.WARNING,
            true,
            true,
            false,
            1_000L,
            "non-event");
    userAlertManager.register(event);
    userAlertManager.register(nonEvent);
    Set<String> toDump = new HashSet<>();
    toDump.add("event-anchor");

    // Act
    userAlertManager.dumpEvents(new HashSet<>(toDump));

    // Assert
    assertTrue(event.dismissed());
    assertArrayEquals(new UserAlert[] {nonEvent}, userAlertManager.getAlerts());
  }

  @Test
  void watch_whenExistingValidAlerts_expectSubscriberReceivesMessages() {
    // Arrange
    TestAlert validAlert =
        new TestAlert(
            true, "Valid", "Text", "Short", UserAlert.ERROR, true, true, false, 1_000L, "valid");
    TestAlert invalidAlert =
        new TestAlert(
            true,
            "Invalid",
            "Text",
            "Short",
            UserAlert.ERROR,
            false,
            true,
            false,
            1_000L,
            "invalid");
    userAlertManager.register(validAlert);
    userAlertManager.register(invalidAlert);
    FCPConnectionHandler subscriber = mock(FCPConnectionHandler.class);

    // Act
    userAlertManager.watch(subscriber);

    // Assert
    verify(subscriber).send(validAlert.getFCPMessage());
    verify(subscriber, never()).send(invalidAlert.getFCPMessage());
  }

  @Test
  void watch_whenNewAlertRegistered_expectSubscriberNotified() {
    // Arrange
    FCPConnectionHandler subscriber = mock(FCPConnectionHandler.class);
    userAlertManager.watch(subscriber);
    TestAlert alert =
        new TestAlert(
            true, "Title", "Text", "Short", UserAlert.ERROR, true, true, false, 1_000L, "notify");

    // Act
    userAlertManager.register(alert);

    // Assert
    verify(subscriber).send(alert.getFCPMessage());
  }

  @Test
  void unwatch_whenSubscriberRemoved_expectNoFurtherNotifications() {
    // Arrange
    FCPConnectionHandler subscriber = mock(FCPConnectionHandler.class);
    userAlertManager.watch(subscriber);
    userAlertManager.unwatch(subscriber);
    TestAlert alert =
        new TestAlert(
            true, "Title", "Text", "Short", UserAlert.ERROR, true, true, false, 1_000L, "notify");

    // Act
    userAlertManager.register(alert);

    // Assert
    verifyNoInteractions(subscriber);
  }

  private static Document parseAtomXml(String atom) throws Exception {
    return DocumentBuilderFactory.newInstance()
        .newDocumentBuilder()
        .parse(new InputSource(new StringReader(atom)));
  }

  private static List<EntrySnapshot> getEntrySnapshots(Document atomXml) throws Exception {
    NodeList nodeList = (NodeList) X_PATH.evaluate("/feed/entry", atomXml, XPathConstants.NODESET);
    List<EntrySnapshot> entries = new ArrayList<>();
    for (int index = 0; index < nodeList.getLength(); index++) {
      entries.add(entrySnapshot(nodeList.item(index)));
    }
    return entries;
  }

  private static EntrySnapshot entrySnapshot(org.w3c.dom.Node node) throws Exception {
    return new EntrySnapshot(
        X_PATH.evaluate("id", node),
        X_PATH.evaluate("link/@href", node),
        X_PATH.evaluate("updated", node),
        X_PATH.evaluate("title", node),
        X_PATH.evaluate("summary", node),
        X_PATH.evaluate("content[@type='text']", node));
  }

  private static EntrySnapshot entryFor(TestAlert alert) {
    return new EntrySnapshot(
        "urn:feed:" + alert.anchor(),
        "http://test/alerts/#" + alert.anchor(),
        formatTime(alert.getUpdatedTime()),
        alert.getTitle(),
        alert.getShortText(),
        alert.getText());
  }

  private static String formatTime(long time) {
    return "%tY-%<tm-%<tdT%<tH:%<tM:%<tS%0+3d:%02d"
        .formatted(
            time,
            MILLISECONDS.toHours(TimeZone.getDefault().getOffset(time)),
            MILLISECONDS.toMinutes(TimeZone.getDefault().getOffset(time)) % 60);
  }

  private static class TestAlert extends AbstractUserAlert {
    private final boolean eventNotification;
    private final long updatedTime;
    private final String anchor;
    private final FCPMessage fcpMessage;
    private boolean dismissed;

    private TestAlert(
        boolean canDismiss,
        String title,
        String text,
        String shortText,
        short priority,
        boolean valid,
        boolean unregisterOnDismiss,
        boolean eventNotification,
        long updatedTime,
        String anchor) {
      super(
          canDismiss,
          title,
          Body.of(text, shortText, new HTMLNode("div", text)),
          priority,
          valid,
          new DismissOptions("Dismiss", unregisterOnDismiss));
      this.eventNotification = eventNotification;
      this.updatedTime = updatedTime;
      this.anchor = anchor;
      this.fcpMessage = mock(FCPMessage.class);
    }

    @Override
    public boolean isEventNotification() {
      return eventNotification;
    }

    @Override
    public long getUpdatedTime() {
      return updatedTime;
    }

    @Override
    public String anchor() {
      return anchor;
    }

    @Override
    public FCPMessage getFCPMessage() {
      return fcpMessage;
    }

    @Override
    public void onDismiss() {
      dismissed = true;
    }

    boolean dismissed() {
      return dismissed;
    }
  }

  private static final class TestEvent extends TestAlert implements UserEvent {
    private final Type eventType;

    private TestEvent(
        Type eventType,
        boolean canDismiss,
        String title,
        String text,
        String shortText,
        short priority,
        boolean valid,
        boolean unregisterOnDismiss,
        boolean eventNotification,
        long updatedTime,
        String anchor) {
      super(
          canDismiss,
          title,
          text,
          shortText,
          priority,
          valid,
          unregisterOnDismiss,
          eventNotification,
          updatedTime,
          anchor);
      this.eventType = eventType;
    }

    @Override
    public Type getEventType() {
      return eventType;
    }
  }

  private static void installBase(BaseL10n base) throws ReflectiveOperationException {
    Method setBase = NodeL10n.class.getDeclaredMethod("setBase", BaseL10n.class);
    setBase.setAccessible(true);
    setBase.invoke(null, base);
  }

  private record EntrySnapshot(
      String id, String link, String updated, String title, String summary, String content) {}
}

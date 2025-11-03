package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.ref.WeakReference;
import java.util.Locale;
import java.util.TimeZone;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.TextFeedMessage;
import network.crypta.io.comm.Peer;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class N2NTMUserAlertTest {

  @Mock private DarknetPeerNode mockPeerNode;

  private Locale originalLocale;
  private TimeZone originalTimeZone;

  @BeforeEach
  void setUp() {
    // Ensure deterministic date/time formatting and locale-dependent strings in tests
    originalLocale = Locale.getDefault();
    originalTimeZone = TimeZone.getDefault();
    Locale.setDefault(Locale.US);
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    // Initialize NodeL10n to English explicitly for predictable messages
    new NodeL10n(LANGUAGE.ENGLISH, new File("."));
  }

  @AfterEach
  void tearDown() {
    Locale.setDefault(originalLocale);
    TimeZone.setDefault(originalTimeZone);
  }

  @Test
  void getTitle_whenInitialized_expectLocalizedTitle() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);

    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "Hello", 7, 0L, 1_000L, 2_000L, 123L);

    // Act
    String title = alert.getTitle();

    // Assert
    assertEquals(
        "Node to Node Text Message 7 from Alice (example.com:1234)",
        title,
        "Title must interpolate file number, peername, and peer address");
  }

  @Test
  void getText_and_getShortText_whenInitialized_expectHeaderAndSummary() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);

    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "Hello", 7, 0L, 1_000L, 2_000L, 123L);

    // Act
    String text = alert.getText();
    String shortText = alert.getShortText();

    // Assert (avoid asserting full DateFormat output; check stable structure + message)
    assertTrue(
        text.startsWith("From: Alice ("), "Header should start with localized 'From' and name");
    assertTrue(text.endsWith("): Hello"), "Full text should end with ': ' followed by the message");
    assertEquals(
        "Message from Alice", shortText, "Short text should be a concise localized summary");
  }

  @Test
  void getHTMLText_whenPeerPresent_expectReplyLinkAndLineBreaks() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);

    String message = "Line1\nLine2";
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, message, 42, 0L, 1_000L, 2_000L, 999L);

    // Act
    HTMLNode html = alert.getHTMLText();
    String rendered = html.generate();

    // Assert
    assertTrue(rendered.contains("Line1"), "First line should be present in HTML");
    assertTrue(rendered.contains("Line2"), "Second line should be present in HTML");
    assertTrue(rendered.contains("<br />"), "Newline should be rendered as a <br />");
    String expectedHref = "/send_n2ntm/?peernode_hashcode=" + mockPeerNode.hashCode();
    assertTrue(rendered.contains(expectedHref), "Reply link should include peer hashcode in href");
    assertTrue(rendered.contains(">Reply<"), "Reply link text should be localized");
  }

  @Test
  void getHTMLText_whenPeerMissing_expectNoReplyLink() throws Exception {
    // Arrange
    Peer peer = new Peer("example.net:4321", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(null));
    when(mockPeerNode.getName()).thenReturn("Bob");
    when(mockPeerNode.getPeer()).thenReturn(peer);
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "Msg", 5, 0L, 1_000L, 2_000L, 111L);

    // Act
    String rendered = alert.getHTMLText().generate();

    // Assert
    assertTrue(rendered.contains("Msg"), "Message text should be present");
    assertFalse(
        rendered.contains("/send_n2ntm/?peernode_hashcode="),
        "No reply link should be rendered when peer reference is cleared");
  }

  @Test
  void onDismiss_whenPeerPresent_expectDeleteCalled() throws Exception {
    // Arrange
    Peer peer = new Peer("node.local:5555", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Carol");
    when(mockPeerNode.getPeer()).thenReturn(peer);
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "X", 77, 0L, 1_000L, 2_000L, 1L);

    // Act
    alert.onDismiss();

    // Assert
    verify(mockPeerNode).deleteExtraPeerDataFile(77);
  }

  @Test
  void onDismiss_whenPeerMissing_expectDeleteNotCalled() throws Exception {
    // Arrange
    Peer peer = new Peer("node.local:5555", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(null));
    when(mockPeerNode.getName()).thenReturn("Carol");
    when(mockPeerNode.getPeer()).thenReturn(peer);
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "X", 88, 0L, 1_000L, 2_000L, 1L);

    // Act
    alert.onDismiss();

    // Assert
    verify(mockPeerNode, never()).deleteExtraPeerDataFile(88);
  }

  @Test
  void getFCPMessage_whenConstructed_expectFieldSetContainsSourceAndTimes() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);

    long composed = 0L;
    long sent = 1_000L;
    long received = 2_000L;
    String messageText = "Hello";

    N2NTMUserAlert alert =
        new N2NTMUserAlert(mockPeerNode, messageText, 7, composed, sent, received, 123L);

    // Act
    FCPMessage fcp = alert.getFCPMessage();

    // Assert
    assertNotNull(fcp, "FCP message must not be null");
    assertEquals(TextFeedMessage.NAME, fcp.getName());
    var fs = fcp.getFieldSet();
    assertEquals("Alice", fs.get("SourceNodeName"));
    assertEquals(Long.toString(composed), fs.get("TimeComposed"));
    assertEquals(Long.toString(sent), fs.get("TimeSent"));
    assertEquals(Long.toString(received), fs.get("TimeReceived"));
    // Verify the additional bucket length for MessageText is present and equals payload size
    assertEquals(Integer.toString(messageText.getBytes().length), fs.get("MessageTextLength"));
  }

  @Test
  void getFCPMessage_whenMessageNull_expectZeroLengthMessageTextBucket() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, null, 7, 0L, 1_000L, 2_000L, 123L);

    // Act
    FCPMessage fcp = alert.getFCPMessage();

    // Assert
    assertEquals("0", fcp.getFieldSet().get("MessageTextLength"));
  }

  @Test
  void isValid_whenPeerUpdates_expectTitleReflectsNewNameAndPeer() throws Exception {
    // Arrange
    Peer peer1 = new Peer("old.example:100", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("OldName");
    when(mockPeerNode.getPeer()).thenReturn(peer1);
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "Msg", 3, 0L, 1_000L, 2_000L, 55L);

    // Sanity check initial title
    assertTrue(alert.getTitle().contains("OldName"));
    assertTrue(alert.getTitle().contains("old.example:100"));

    // Update peer info: new name and address; isValid() should refresh internal fields
    Peer peer2 = new Peer("new.example:200", true);
    when(mockPeerNode.getName()).thenReturn("NewName");
    when(mockPeerNode.getPeer()).thenReturn(peer2);

    // Act
    boolean stillValid = alert.isValid();

    // Assert
    assertTrue(stillValid, "isValid should always return true");
    String updatedTitle = alert.getTitle();
    assertTrue(updatedTitle.contains("NewName"), "Title should refresh to the latest peer name");
    assertTrue(
        updatedTitle.contains("new.example:200"),
        "Title should refresh to the latest peer address");
  }

  @Test
  void constructor_withoutMsgId_expectMsgIdNegativeOne() throws Exception {
    // Arrange
    Peer peer = new Peer("example.com:1234", true);
    when(mockPeerNode.getWeakRef()).thenReturn(new WeakReference<>(mockPeerNode));
    when(mockPeerNode.getName()).thenReturn("Alice");
    when(mockPeerNode.getPeer()).thenReturn(peer);

    // Act
    N2NTMUserAlert alert = new N2NTMUserAlert(mockPeerNode, "Hello", 1, 0L, 1L, 2L);

    // Assert
    assertEquals(-1L, alert.getMsgid());
    assertEquals(2L, alert.getUpdatedTime(), "Updated time should equal received time");
    assertEquals(0L, alert.getComposedTime());
    assertEquals(1L, alert.getSentTime());
    assertEquals(1, alert.getFileNumber());
    assertEquals("Hello", alert.getMessageText());
  }
}

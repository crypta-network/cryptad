package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.URIFeedMessage;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // descriptive test method names
class DownloadFeedUserAlertTest {

  @Test
  void title_text_html_whenDescriptionPresent_expectLocalizedAndStructured()
      throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Alice");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));

    FreenetURI uri = new FreenetURI("KSK@readme.txt");
    String description = "Line1\nLine2";
    DownloadFeedUserAlert alert =
        new DownloadFeedUserAlert(peer, description, 42, uri, 1111L, 2222L, 3333L);

    // Act
    String title = alert.getTitle();
    String shortText = alert.getShortText();
    String text = alert.getText();
    HTMLNode html = alert.getHTMLText();

    // Assert: title and short text use l10n with the peer name
    assertEquals("Alice recommends you a file", title);
    assertEquals(title, shortText);

    // Assert: text includes URI and description labels and content
    assertEquals("URI: " + uri + "\n" + "Description: " + description, text);

    // Assert: HTML structure
    assertNotNull(html);
    assertEquals("div", html.getName());
    var children = html.getChildren();
    // Expect: <a href="/KSK@readme.txt">KSK@readme.txt</a>
    HTMLNode a = children.getFirst();
    assertEquals("a", a.getName());
    assertEquals("/" + uri, a.getAttribute("href"));
    assertEquals("#", a.getChildren().getFirst().getName());
    assertEquals(uri.toShortString(), a.getChildren().getFirst().getContent());

    // Followed by <br/><br/>Description:<br/>Line1<br/>Line2
    assertEquals("br", children.get(1).getName());
    assertEquals("br", children.get(2).getName());
    assertEquals("#", children.get(3).getName());
    assertEquals("Description:", children.get(3).getContent());
    assertEquals("br", children.get(4).getName());
    assertEquals("#", children.get(5).getName());
    assertEquals("Line1", children.get(5).getContent());
    assertEquals("br", children.get(6).getName());
    assertEquals("#", children.get(7).getName());
    assertEquals("Line2", children.get(7).getContent());

    // Also verify dismiss button label is localized
    assertEquals("Delete", alert.dismissButtonText());
    // Priority is minor
    assertEquals(UserAlert.MINOR, alert.getPriorityClass());
  }

  @Test
  void text_whenDescriptionNull_expectOnlyUriLine() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Bob");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));

    FreenetURI uri = new FreenetURI("KSK@file.txt");
    DownloadFeedUserAlert alert = new DownloadFeedUserAlert(peer, null, 7, uri, 1L, -1L, -1L);

    // Act
    String text = alert.getText();
    HTMLNode html = alert.getHTMLText();

    // Assert
    assertEquals("URI: " + uri + "\n", text);
    assertEquals("div", html.getName());
    var children = html.getChildren();
    // Only anchor should be present when description is null
    assertEquals(1, children.size());
    assertEquals("a", children.getFirst().getName());
  }

  @Test
  void html_whenDescriptionEmpty_expectNoDescriptionBlock() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Carol");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@x.txt");
    DownloadFeedUserAlert alert = new DownloadFeedUserAlert(peer, "", 3, uri, -1L, -1L, -1L);

    // Act
    HTMLNode html = alert.getHTMLText();

    // Assert: only the anchor element present
    assertEquals(1, html.getChildren().size());
    assertEquals("a", html.getChildren().getFirst().getName());
  }

  @Test
  void onDismiss_whenPeerPresent_invokesDeletion() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Dave");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@offer.txt");
    int fileNumber = 99;
    DownloadFeedUserAlert alert =
        new DownloadFeedUserAlert(peer, "desc", fileNumber, uri, 10L, 20L, 30L);

    // Act
    alert.onDismiss();

    // Assert
    verify(peer).deleteExtraPeerDataFile(fileNumber);
  }

  @Test
  void onDismiss_whenPeerReferenceGone_doesNothing() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Eve");
    // The weak reference resolves to null
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(null));
    FreenetURI uri = new FreenetURI("KSK@abc.txt");
    DownloadFeedUserAlert alert = new DownloadFeedUserAlert(peer, null, 5, uri, -1L, -1L, -1L);

    // Act
    alert.onDismiss();

    // Assert: no deletion attempted
    verify(peer, never()).deleteExtraPeerDataFile(anyInt());
  }

  @Test
  void isValid_whenPeerNameChanges_updatesTitle() throws MalformedURLException {
    // Arrange: first call returns initial name (constructor), second call returns updated name
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Alice", "Mallory");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@z.txt");
    DownloadFeedUserAlert alert = new DownloadFeedUserAlert(peer, null, 1, uri, -1L, -1L, -1L);

    // Sanity: initial title uses first name
    assertEquals("Alice recommends you a file", alert.getTitle());

    // Act: isValid() refreshes source node name from the weak reference
    boolean stillValid = alert.isValid();

    // Assert
    assertTrue(stillValid);
    assertEquals("Mallory recommends you a file", alert.getTitle());
  }

  @Test
  void getFCPMessage_whenPopulated_expectURIFeedWithFields() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Frank");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@data.bin");
    String description = "hello"; // 5 bytes in UTF-8
    DownloadFeedUserAlert alert =
        new DownloadFeedUserAlert(peer, description, 11, uri, 123L, -1L, 789L);

    long updatedTime = alert.getUpdatedTime();
    String expectedTitle = alert.getTitle();
    String expectedShort = alert.getShortText();
    int expectedPriority = alert.getPriorityClass();
    int descriptionLen = description.getBytes(StandardCharsets.UTF_8).length;

    // Act
    FCPMessage msg = alert.getFCPMessage();

    // Assert basic type
    URIFeedMessage uriMsg = assertInstanceOf(URIFeedMessage.class, msg);
    assertEquals("URIFeed", uriMsg.getName());

    // Assert fields present and correct
    SimpleFieldSet fs = uriMsg.getFieldSet();
    assertEquals(expectedTitle, fs.get("Header"));
    assertEquals(expectedShort, fs.get("ShortText"));
    assertEquals(Integer.toString(expectedPriority), fs.get("PriorityClass"));
    assertEquals(Long.toString(updatedTime), fs.get("UpdatedTime"));
    assertEquals("Frank", fs.get("SourceNodeName"));
    assertEquals(uri.toString(), fs.get("URI"));
    assertEquals(Integer.toString(descriptionLen), fs.get("DescriptionLength"));
    // composed was set, sent omitted (-1), received set
    assertEquals(Long.toString(123L), fs.get("TimeComposed"));
    assertNull(fs.get("TimeSent"));
    assertEquals(Long.toString(789L), fs.get("TimeReceived"));

    // DataLength is sum of bucket sizes; at least check it's >= text length + description length
    int textLen = alert.getText().getBytes(StandardCharsets.UTF_8).length;
    int dataLen = Integer.parseInt(fs.get("DataLength"));
    assertEquals(textLen + descriptionLen, dataLen);
  }
}

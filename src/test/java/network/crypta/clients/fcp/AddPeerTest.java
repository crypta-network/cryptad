package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.OpennetPeerNode;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S2095", "resource"})
@ExtendWith(MockitoExtension.class)
class AddPeerTest {

  private static final String IDENTIFIER = "test-ident";

  @Test
  void constructor_whenTrustMissing_throwsMessageInvalidExceptionWithMissingFieldCode() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    // No Trust field
    fs.putSingle("Visibility", FRIEND_VISIBILITY.YES.name());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new AddPeer(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("AddPeer requires Trust", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void constructor_whenTrustInvalid_throwsMessageInvalidExceptionWithInvalidFieldCode() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Trust", "NOT_A_VALID_VALUE");
    fs.putSingle("Visibility", FRIEND_VISIBILITY.YES.name());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new AddPeer(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("Invalid Trust value on AddPeer", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void constructor_whenVisibilityMissing_throwsMessageInvalidExceptionWithMissingFieldCode() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Trust", FRIEND_TRUST.NORMAL.name());
    // No Visibility field

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new AddPeer(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("AddPeer requires Visibility", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void constructor_whenVisibilityInvalid_throwsMessageInvalidExceptionWithInvalidFieldCode() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Trust", FRIEND_TRUST.NORMAL.name());
    fs.putSingle("Visibility", "NOT_A_VALID_VALUE");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new AddPeer(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("Invalid Visibility value on AddPeer", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void getName_whenCalled_returnsAddPeerConstant() throws MessageInvalidException {
    SimpleFieldSet fs = minimalValidFieldSet();

    AddPeer addPeer = new AddPeer(fs);

    assertEquals(AddPeer.NAME, addPeer.getName());
  }

  @Test
  void getFieldSet_whenCalled_returnsNonNullEmptyFieldSet() throws MessageInvalidException {
    SimpleFieldSet fs = minimalValidFieldSet();

    AddPeer addPeer = new AddPeer(fs);

    SimpleFieldSet result = addPeer.getFieldSet();
    assertNotNull(result);
    // A freshly created SimpleFieldSet should not contain user data yet.
    assertNull(result.get("Identifier"));
  }

  @Test
  void getReferenceFromURL_whenFileHasTwoLines_readsBothLinesWithTrailingNewlines(
      @TempDir Path tempDir) throws IOException {
    Path file = tempDir.resolve("peer-ref.txt");
    Files.writeString(file, "line1\nline2\n", StandardCharsets.UTF_8);

    URL url = file.toUri().toURL();

    StringBuilder result = AddPeer.getReferenceFromURL(url);

    assertEquals("line1\nline2\n", result.toString());
  }

  @Test
  void getReferenceFromFreenetURI_whenClientReturnsBucket_readsBucketContent() throws Exception {
    Bucket bucket = new ArrayBucket();
    try (OutputStream out = bucket.getOutputStream()) {
      out.write("ref-line-1\nref-line-2\n".getBytes(StandardCharsets.UTF_8));
    }

    FetchResult fetchResult = new FetchResult(new ClientMetadata("text/plain"), bucket);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    when(client.fetch(any(FreenetURI.class), eq(31000L))).thenReturn(fetchResult);

    FreenetURI uri = mock(FreenetURI.class);

    StringBuilder result = AddPeer.getReferenceFromFreenetURI(uri, client);

    assertEquals("ref-line-1\nref-line-2\n", result.toString());
  }

  @Test
  void run_whenHandlerHasNoFullAccess_throwsAccessDenied() throws MessageInvalidException {
    SimpleFieldSet fs = minimalValidFieldSet();
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(false);
    Node node = mock(Node.class);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("AddPeer requires full access", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
    verifyNoMoreInteractions(node);
  }

  @Test
  void run_whenOpennetRefCreatesPeer_addsPeerAndSendsPeerMessage() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    OpennetPeerNode peerNode = mock(OpennetPeerNode.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class))).thenReturn(peerNode);
    when(node.getOpennetPubKeyHash()).thenReturn(new byte[] {1});
    when(node.addPeerConnection(peerNode)).thenReturn(true);

    addPeer.run(handler, node);

    verify(node).createNewOpennetNode(any(SimpleFieldSet.class));
    verify(node).addPeerConnection(peerNode);
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(messageCaptor.capture());
    FCPMessage sent = messageCaptor.getValue();
    assertNotNull(sent);
    assertEquals(PeerMessage.class, sent.getClass());
    PeerMessage peerMessage = (PeerMessage) sent;
    assertEquals(IDENTIFIER, peerMessage.messageIdentifier);
  }

  @Test
  void run_whenDarknetRefCreatesPeer_addsPeerWithConfiguredTrustAndVisibility() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    // No opennet flag -> darknet
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    DarknetPeerNode peerNode = mock(DarknetPeerNode.class);
    when(node.getDarknetPubKeyHash()).thenReturn(new byte[] {1});
    when(node.addPeerConnection(peerNode)).thenReturn(true);

    when(node.createNewDarknetNode(
            any(SimpleFieldSet.class), any(FRIEND_TRUST.class), any(FRIEND_VISIBILITY.class)))
        .thenReturn(peerNode);

    addPeer.run(handler, node);

    ArgumentCaptor<FRIEND_TRUST> trustCaptor = ArgumentCaptor.forClass(FRIEND_TRUST.class);
    ArgumentCaptor<FRIEND_VISIBILITY> visibilityCaptor =
        ArgumentCaptor.forClass(FRIEND_VISIBILITY.class);

    verify(node)
        .createNewDarknetNode(
            any(SimpleFieldSet.class), trustCaptor.capture(), visibilityCaptor.capture());
    verify(node).addPeerConnection(peerNode);

    assertEquals(FRIEND_TRUST.NORMAL, trustCaptor.getValue());
    assertEquals(FRIEND_VISIBILITY.YES, visibilityCaptor.getValue());
  }

  @Test
  void run_whenOpennetRefIsSelf_throwsCannotPeerWithSelf() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    OpennetPeerNode peerNode = mock(OpennetPeerNode.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class))).thenReturn(peerNode);
    when(node.getOpennetPubKeyHash()).thenReturn(null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.CANNOT_PEER_WITH_SELF, exception.protocolCode);
    verify(node, never()).addPeerConnection(any(PeerNode.class));
  }

  @Test
  void run_whenOpennetRefDuplicatePeer_throwsDuplicatePeerRef() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    OpennetPeerNode peerNode = mock(OpennetPeerNode.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class))).thenReturn(peerNode);
    when(node.getOpennetPubKeyHash()).thenReturn(new byte[] {1});
    when(node.addPeerConnection(peerNode)).thenReturn(false);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.DUPLICATE_PEER_REF, exception.protocolCode);
  }

  @Test
  void run_whenOpennetCreationFailsWithFSParseException_throwsRefParseError() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new FSParseException("parse-error"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.REF_PARSE_ERROR, exception.protocolCode);
  }

  @Test
  void run_whenOpennetCreationFailsWithOpennetDisabled_throwsOpennetDisabledError()
      throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new OpennetDisabledException("disabled"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.OPENNET_DISABLED, exception.protocolCode);
  }

  @Test
  void run_whenOpennetCreationFailsWithInvalidSignature_throwsRefSignatureInvalid()
      throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new ReferenceSignatureVerificationException("bad-sig"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.REF_SIGNATURE_INVALID, exception.protocolCode);
  }

  @Test
  void run_whenOpennetCreationFailsWithPeerTooOld_throwsRefParseError() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    when(node.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new PeerTooOldException("too-old", 1, null));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.REF_PARSE_ERROR, exception.protocolCode);
  }

  @Test
  void run_whenDarknetCreationFailsWithInvalidSignature_throwsRefSignatureInvalid()
      throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    Node node = mock(Node.class);
    when(node.createNewDarknetNode(
            any(SimpleFieldSet.class), any(FRIEND_TRUST.class), any(FRIEND_VISIBILITY.class)))
        .thenThrow(new ReferenceSignatureVerificationException("bad-sig"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.REF_SIGNATURE_INVALID, exception.protocolCode);
  }

  @Test
  void run_whenFilePathIsDirectory_throwsNotAFileError(@TempDir Path tempDir)
      throws MessageInvalidException {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.putSingle("File", tempDir.toString());

    AddPeer addPeer = new AddPeer(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);
    Node node = mock(Node.class);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.NOT_A_FILE_ERROR, exception.protocolCode);
  }

  private SimpleFieldSet minimalValidFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Trust", FRIEND_TRUST.NORMAL.name());
    fs.putSingle("Visibility", FRIEND_VISIBILITY.YES.name());
    return fs;
  }
}

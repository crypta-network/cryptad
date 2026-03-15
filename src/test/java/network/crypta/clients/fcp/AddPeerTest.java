package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S2095"})
@ExtendWith(MockitoExtension.class)
class AddPeerTest {

  private static final String IDENTIFIER = "test-ident";

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private PeerPort peerPort;

  @Test
  void constructor_whenTrustMissing_throwsMessageInvalidExceptionWithMissingFieldCode() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Visibility", PeerVisibility.YES.name());

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
    fs.putSingle("Visibility", PeerVisibility.YES.name());

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
    fs.putSingle("Trust", PeerTrust.NORMAL.name());

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
    fs.putSingle("Trust", PeerTrust.NORMAL.name());
    fs.putSingle("Visibility", "NOT_A_VALID_VALUE");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new AddPeer(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("Invalid Visibility value on AddPeer", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void getName_whenCalled_returnsAddPeerConstant() throws MessageInvalidException {
    AddPeer addPeer = new AddPeer(minimalValidFieldSet());

    assertEquals(AddPeer.NAME, addPeer.getName());
  }

  @Test
  void getFieldSet_whenCalled_returnsNonNullEmptyFieldSet() throws MessageInvalidException {
    AddPeer addPeer = new AddPeer(minimalValidFieldSet());

    SimpleFieldSet result = addPeer.getFieldSet();

    assertNotNull(result);
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

    FetchResult fetchResult = FetchResult.create(new ClientMetadata("text/plain"), bucket);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    when(client.fetch(any(FreenetURI.class), eq(31000L))).thenReturn(fetchResult);

    FreenetURI uri = mock(FreenetURI.class);

    StringBuilder result = AddPeer.getReferenceFromFreenetURI(uri, client);

    assertEquals("ref-line-1\nref-line-2\n", result.toString());
  }

  @Test
  void run_whenHandlerHasNoFullAccess_throwsAccessDenied() throws MessageInvalidException {
    AddPeer addPeer = new AddPeer(minimalValidFieldSet());
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("AddPeer requires full access", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  @Test
  void run_whenOpennetRefAccepted_convertsReferenceAndSendsPeerMessage() throws Exception {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.put("opennet", true);
    AddPeer addPeer = new AddPeer(fs);
    PeerSnapshot snapshot = peerSnapshot("peer-one");
    stubPeerPort();
    when(handler.hasFullAccess()).thenReturn(true);
    when(peerPort.add(any(PeerFieldSet.class), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES)))
        .thenReturn(snapshot);

    addPeer.run(handler, node);

    ArgumentCaptor<PeerFieldSet> referenceCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort).add(referenceCaptor.capture(), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES));
    assertEquals("true", referenceCaptor.getValue().directValues().get("opennet"));
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(messageCaptor.capture());
    PeerMessage peerMessage = (PeerMessage) messageCaptor.getValue();
    assertEquals(snapshot, peerMessage.snapshot);
    assertEquals(IDENTIFIER, peerMessage.messageIdentifier);
    verifyNoInteractions(node);
  }

  @Test
  void run_whenDarknetRefAccepted_mapsConfiguredTrustAndVisibility() throws Exception {
    AddPeer addPeer = new AddPeer(minimalValidFieldSet());
    PeerSnapshot snapshot = peerSnapshot("peer-two");
    stubPeerPort();
    when(handler.hasFullAccess()).thenReturn(true);
    when(peerPort.add(any(PeerFieldSet.class), any(PeerTrust.class), any(PeerVisibility.class)))
        .thenReturn(snapshot);

    addPeer.run(handler, node);

    ArgumentCaptor<PeerTrust> trustCaptor = ArgumentCaptor.forClass(PeerTrust.class);
    ArgumentCaptor<PeerVisibility> visibilityCaptor = ArgumentCaptor.forClass(PeerVisibility.class);
    verify(peerPort)
        .add(any(PeerFieldSet.class), trustCaptor.capture(), visibilityCaptor.capture());
    assertEquals(PeerTrust.NORMAL, trustCaptor.getValue());
    assertEquals(PeerVisibility.YES, visibilityCaptor.getValue());
  }

  @Test
  void run_whenAddRejectedWithRefParse_mapsProtocolCode() throws Exception {
    assertAddRejectedMapsToProtocolCode(
        PeerAddFailureReason.REF_PARSE_ERROR, ProtocolErrorMessage.REF_PARSE_ERROR);
  }

  @Test
  void run_whenAddRejectedWithOpennetDisabled_mapsProtocolCode() throws Exception {
    assertAddRejectedMapsToProtocolCode(
        PeerAddFailureReason.OPENNET_DISABLED, ProtocolErrorMessage.OPENNET_DISABLED);
  }

  @Test
  void run_whenAddRejectedWithInvalidSignature_mapsProtocolCode() throws Exception {
    assertAddRejectedMapsToProtocolCode(
        PeerAddFailureReason.REF_SIGNATURE_INVALID, ProtocolErrorMessage.REF_SIGNATURE_INVALID);
  }

  @Test
  void run_whenAddRejectedWithCannotPeerWithSelf_mapsProtocolCode() throws Exception {
    assertAddRejectedMapsToProtocolCode(
        PeerAddFailureReason.CANNOT_PEER_WITH_SELF, ProtocolErrorMessage.CANNOT_PEER_WITH_SELF);
  }

  @Test
  void run_whenAddRejectedWithDuplicateRef_mapsProtocolCode() throws Exception {
    assertAddRejectedMapsToProtocolCode(
        PeerAddFailureReason.DUPLICATE_PEER_REF, ProtocolErrorMessage.DUPLICATE_PEER_REF);
  }

  @Test
  void run_whenFilePathIsDirectory_throwsNotAFileError(@TempDir Path tempDir)
      throws MessageInvalidException {
    SimpleFieldSet fs = minimalValidFieldSet();
    fs.putSingle("File", tempDir.toString());

    AddPeer addPeer = new AddPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(ProtocolErrorMessage.NOT_A_FILE_ERROR, exception.protocolCode);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
  }

  private void assertAddRejectedMapsToProtocolCode(PeerAddFailureReason reason, int protocolCode)
      throws Exception {
    AddPeer addPeer = new AddPeer(minimalValidFieldSet());
    stubPeerPort();
    when(handler.hasFullAccess()).thenReturn(true);
    when(peerPort.add(any(PeerFieldSet.class), any(PeerTrust.class), any(PeerVisibility.class)))
        .thenThrow(new PeerAddRejectedException(reason, "detail-" + reason.name()));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> addPeer.run(handler, node));

    assertEquals(protocolCode, exception.protocolCode);
    assertEquals("detail-" + reason.name(), exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  private void stubPeerPort() {
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
  }

  private SimpleFieldSet minimalValidFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("Trust", PeerTrust.NORMAL.name());
    fs.putSingle("Visibility", PeerVisibility.YES.name());
    fs.putSingle("identity", "peer-identity");
    return fs;
  }

  private static PeerSnapshot peerSnapshot(String identity) {
    return new PeerSnapshot(new PeerFieldSet(Map.of("identity", identity), Map.of()));
  }
}

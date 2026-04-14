package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPConnectionHandlerTest {

  @Mock private FCPServer server;
  @Mock private FcpServerRuntimeSupport serverRuntimeSupport;
  @Mock private ClientContext clientContext;
  @Mock private Socket socket;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RandomnessPort randomnessPort;
  private FCPConnectionHandler handler;

  @BeforeEach
  void setUp() {
    DeterministicRandomSource randomSource = new DeterministicRandomSource(1234L);
    Random fastRandom = new Random(5678L);

    lenient().when(server.serverRuntimeSupport()).thenReturn(serverRuntimeSupport);
    lenient().when(serverRuntimeSupport.clientContext()).thenReturn(clientContext);
    lenient().when(server.runtime()).thenReturn(runtimePorts);
    lenient().when(runtimePorts.randomness()).thenReturn(randomnessPort);
    lenient()
        .doAnswer(
            invocation -> {
              byte[] target = invocation.getArgument(0);
              randomSource.nextBytes(target);
              return null;
            })
        .when(randomnessPort)
        .fillSecureRandom(any(byte[].class));
    lenient().when(randomnessPort.fastWeakRandom()).thenReturn(fastRandom);

    handler = new FCPConnectionHandler(socket, server);
  }

  @Test
  void send_whenMessageNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> handler.send(null));
  }

  @Test
  void send_whenQueueHasCapacity_enqueuesMessage() {
    FCPMessage message = mock(FCPMessage.class);
    when(server.maxMessageQueueLength()).thenReturn(10);
    when(server.neverDropAMessage()).thenReturn(false);

    handler.send(message);

    Deque<FCPMessage> queue = handler.getOutputHandler().outQueue;
    assertEquals(1, queue.size());
    assertSame(message, queue.peekLast());
  }

  @Test
  void send_whenQueueFullAndDroppingAllowed_doesNotQueueNewMessage() {
    Deque<FCPMessage> queue = handler.getOutputHandler().outQueue;
    queue.add(mock(FCPMessage.class));
    when(server.maxMessageQueueLength()).thenReturn(1);
    when(server.neverDropAMessage()).thenReturn(false);

    handler.send(mock(FCPMessage.class));

    assertEquals(1, queue.size());
  }

  @Test
  void send_whenQueueFullAndDroppingDisabled_enqueuesMessage() {
    Deque<FCPMessage> queue = handler.getOutputHandler().outQueue;
    queue.add(mock(FCPMessage.class));
    when(server.maxMessageQueueLength()).thenReturn(1);
    when(server.neverDropAMessage()).thenReturn(true);
    FCPMessage message = mock(FCPMessage.class);

    handler.send(message);

    assertEquals(2, queue.size());
    assertSame(message, queue.peekLast());
  }

  @Test
  void removeRequestByIdentifier_whenKillTrue_cancelsAndNotifies() {
    ClientRequest request = mock(ClientRequest.class);
    handler.requestsByIdentifier.put("id", request);

    ClientRequest removed = handler.removeRequestByIdentifier("id", true);

    assertSame(request, removed);
    verify(request).cancel(clientContext);
    verify(request).requestWasRemoved(clientContext);
    verifyNoMoreInteractions(request);
  }

  @Test
  void removeRequestByIdentifier_whenKillFalse_onlyNotifies() {
    ClientRequest request = mock(ClientRequest.class);
    handler.requestsByIdentifier.put("id", request);

    ClientRequest removed = handler.removeRequestByIdentifier("id", false);

    assertSame(request, removed);
    verify(request).requestWasRemoved(clientContext);
    verifyNoMoreInteractions(request);
  }

  @Test
  void allowDDAFrom_withoutCachedEntry_returnsServerPolicy(@TempDir Path tempDir)
      throws IOException {
    File file = tempDir.resolve("test.txt").toFile();
    if (!file.exists()) {
      assertTrue(file.createNewFile());
    }
    when(server.isDownloadDDAAlwaysAllowed()).thenReturn(false);

    assertFalse(handler.ddaAccessController().allowDDAFrom(file, true));
  }

  @Test
  void registerTestDDAResult_thenAllowDDAFrom_respectsCachedPermissions(@TempDir Path tempDir)
      throws IOException {
    File dir = tempDir.toFile();
    handler.registerTestDDAResult(dir.getCanonicalPath(), true, false);
    File child = new File(dir, "foo.bin");
    if (!child.exists()) {
      assertTrue(child.createNewFile());
    }

    assertTrue(handler.ddaAccessController().allowDDAFrom(child, false));
    assertFalse(handler.ddaAccessController().allowDDAFrom(child, true));
  }

  @Test
  void enqueueDDACheck_withInvalidDirectory_throwsException(@TempDir Path tempDir)
      throws IOException {
    File file = tempDir.resolve("not-a-dir").toFile();
    if (!file.exists()) {
      assertTrue(file.createNewFile());
    }
    String invalidPath = file.getPath();

    assertThrows(
        IllegalArgumentException.class, () -> handler.enqueueDDACheck(invalidPath, true, true));
  }

  @Test
  void enqueueDDACheck_whenJobAlreadyInFlight_throws(@TempDir Path tempDir) {
    String directory = tempDir.toString();
    handler.enqueueDDACheck(directory, true, false);

    assertThrows(
        IllegalArgumentException.class, () -> handler.enqueueDDACheck(directory, true, false));
  }

  @Test
  void enqueueAndPopDDACheck_roundTripCreatesAndRemovesJob(@TempDir Path tempDir) throws Exception {
    DdaCheckJob job = handler.enqueueDDACheck(tempDir.toString(), true, true);

    assertNotNull(job);
    assertNotNull(job.directory);
    assertTrue(job.directory.exists());
    DdaCheckJob popped = handler.popDDACheck(tempDir.toString());
    assertSame(job, popped);
    if (job.readFilename != null) {
      String content = Files.readString(job.readFilename.toPath(), StandardCharsets.UTF_8);
      assertEquals(job.readContent, content);
      assertTrue(job.readFilename.delete());
    }
    if (job.writeFilename != null && job.writeFilename.exists()) {
      assertTrue(job.writeFilename.delete());
    }
  }

  @Test
  void freeDDAJobs_deletesOutstandingFiles(@TempDir Path tempDir) {
    DdaCheckJob job = handler.enqueueDDACheck(tempDir.toString(), true, false);
    assertNotNull(job.readFilename);
    assertTrue(job.readFilename.exists());

    handler.freeDDAJobs();

    assertFalse(job.readFilename.exists());
  }

  @Test
  void addUSKSubscription_whenDuplicate_throws() throws IdentifierCollisionException {
    SubscribeUSK usk = mock(SubscribeUSK.class);
    handler.addUSKSubscription("sub", usk);

    assertThrows(IdentifierCollisionException.class, () -> handler.addUSKSubscription("sub", usk));
  }

  @Test
  void unsubscribeUSK_whenIdentifierMissing_throws() {
    assertThrows(MessageInvalidException.class, () -> handler.unsubscribeUSK("missing"));
  }

  @Test
  void unsubscribeUSK_whenPresent_callsUnsubscribe() throws Exception {
    SubscribeUSK subscription = mock(SubscribeUSK.class);
    handler.addUSKSubscription("sub", subscription);

    handler.unsubscribeUSK("sub");

    verify(subscription).unsubscribe();
  }

  @Test
  void connectionRequestClient_whenRealTimeTrue_returnsRealTimeClient() {
    RequestClient client = handler.connectionRequestClient(true);

    assertTrue(client.realTimeFlag());
    assertFalse(client.persistent());
  }

  @Test
  void connectionRequestClient_whenRealTimeFalse_returnsBulkClient() {
    RequestClient client = handler.connectionRequestClient(false);

    assertFalse(client.realTimeFlag());
    assertFalse(client.persistent());
  }

  @Test
  void startClientPut_whenConnectionPersistence_startsWithInsertRuntimeContext() throws Exception {
    ClientPutMessage message = newClientPutMessage("put-connection", "connection");

    try (MockedConstruction<ClientPut> ignored = mockConstruction(ClientPut.class)) {
      handler.startClientPut(message);

      ClientPut request = ignored.constructed().getFirst();
      verify(request).start(clientContext);
    }
  }

  @Test
  void startClientPut_whenRebootPersistence_startsWithInsertRuntimeContext() throws Exception {
    ClientPutMessage message = newClientPutMessage("put-reboot", "reboot");

    try (MockedConstruction<ClientPut> ignored = mockConstruction(ClientPut.class)) {
      handler.startClientPut(message);

      ClientPut request = ignored.constructed().getFirst();
      verify(request).register(false);
      verify(request).start(clientContext);
    }
  }

  @Test
  void startClientPutDir_whenConnectionPersistence_startsWithInsertRuntimeContext(
      @TempDir Path tempDir) throws Exception {
    ClientPutDiskDirMessage message = newClientPutDirMessage(tempDir, "connection");
    Map<String, Object> buckets = new HashMap<>();

    try (MockedConstruction<ClientPutDir> ignored = mockConstruction(ClientPutDir.class)) {
      handler.startClientPutDir(message, buckets, true);

      ClientPutDir request = ignored.constructed().getFirst();
      verify(request).start(clientContext);
    }
  }

  @Test
  void startClientPutDir_whenRebootPersistence_startsWithInsertRuntimeContext(@TempDir Path tempDir)
      throws Exception {
    ClientPutDiskDirMessage message = newClientPutDirMessage(tempDir, "reboot");
    Map<String, Object> buckets = new HashMap<>();

    try (MockedConstruction<ClientPutDir> ignored = mockConstruction(ClientPutDir.class)) {
      handler.startClientPutDir(message, buckets, true);

      ClientPutDir request = ignored.constructed().getFirst();
      verify(request).register(false);
      verify(request).start(clientContext);
    }
  }

  private static ClientPutMessage newClientPutMessage(String identifier, String persistence)
      throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("URI", "CHK@");
    fs.putSingle("UploadFrom", "direct");
    fs.put("DataLength", 4L);
    fs.putSingle("Persistence", persistence);
    return new ClientPutMessage(fs);
  }

  private static ClientPutDiskDirMessage newClientPutDirMessage(Path dir, String persistence)
      throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "dir-id");
    fs.putSingle("URI", "KSK@site");
    fs.putSingle("Filename", dir.toString());
    fs.putSingle("Persistence", persistence);
    return new ClientPutDiskDirMessage(fs);
  }

  private static final class DeterministicRandomSource extends RandomSource {
    DeterministicRandomSource(long seed) {
      super();
      setSeed(seed);
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No-op: deterministic test double does not allocate external resources.
    }
  }
}

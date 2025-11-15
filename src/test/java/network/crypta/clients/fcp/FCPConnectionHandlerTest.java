package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Deque;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPConnectionHandlerTest {

  @Mock private FCPServer server;
  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private TempBucketFactory tempBucketFactory;
  @Mock private Socket socket;
  @Mock private Node node;

  private FCPConnectionHandler handler;
  private Random fastRandom;

  @BeforeEach
  void setUp() {
    DeterministicRandomSource randomSource = new DeterministicRandomSource(1234L);
    fastRandom = new Random(5678L);

    lenient().when(server.getCore()).thenReturn(core);
    lenient().when(core.getTempBucketFactory()).thenReturn(tempBucketFactory);
    lenient().when(server.getNode()).thenReturn(node);
    lenient().when(node.getRandom()).thenReturn(randomSource);

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
    when(core.getClientContext()).thenReturn(clientContext);

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
    when(core.getClientContext()).thenReturn(clientContext);

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
    when(node.getFastWeakRandom()).thenReturn(fastRandom);
    String directory = tempDir.toString();
    handler.enqueueDDACheck(directory, true, false);

    assertThrows(
        IllegalArgumentException.class, () -> handler.enqueueDDACheck(directory, true, false));
  }

  @Test
  void enqueueAndPopDDACheck_roundTripCreatesAndRemovesJob(@TempDir Path tempDir) throws Exception {
    when(node.getFastWeakRandom()).thenReturn(fastRandom);
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
    when(node.getFastWeakRandom()).thenReturn(fastRandom);
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

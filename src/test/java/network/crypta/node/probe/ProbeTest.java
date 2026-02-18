package network.crypta.node.probe;

import network.crypta.config.PersistentConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProbeTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNode source;
  @Mock private network.crypta.node.PeerTransport transport;
  @Mock private RandomSource random;

  private Probe probe;

  @BeforeEach
  void setUp() {
    // Real config tree to satisfy Probe's constructor wiring without heavy mocking.
    PersistentConfig cfg = new PersistentConfig(null);
    cfg.createSubConfig("node"); // Probe looks up this sub-config by name

    when(node.getConfig()).thenReturn(cfg);

    // Deterministic RNG used by Probe for identifier selection and any exponential waits.
    when(random.nextLong()).thenReturn(42L);
    when(random.nextFloat()).thenReturn(0.5f);
    when(random.nextDouble()).thenReturn(0.5d);
    when(node.getRandom()).thenReturn(random);

    // Default: no peers connected so routing fails with DISCONNECTED immediately.
    when(node.network().connectedPeers()).thenReturn(new PeerNode[0]);

    // Source peer is connected and can accept async sends.
    when(source.isConnected()).thenReturn(true);
    when(source.userToString()).thenReturn("peer-1");
    when(source.getIdentityString()).thenReturn("id-1");
    when(source.transport()).thenReturn(transport);

    probe = new Probe(node);
  }

  @Test
  void request_whenInvalidType_expectUnrecognizedTypeErrorRelayed() throws Exception {
    // Arrange
    long uid = 123L;
    Message msg = new Message(DMT.ProbeRequest);
    msg.set(DMT.HTL, (byte) 1);
    msg.set(DMT.UID, uid);
    // Use an out-of-range type code to trigger UNRECOGNIZED_TYPE
    msg.set(DMT.TYPE, (byte) 42);

    // Act
    probe.request(msg, source);

    // Assert
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport, atLeast(1)).sendAsync(captor.capture(), any(), any());
    Message sent = captor.getAllValues().getLast();
    assertThat("Should relay a ProbeError", sent.getSpec(), is(DMT.ProbeError));
    assertThat(sent.getLong(DMT.UID), is(uid));
    assertThat(sent.getByte(DMT.TYPE), is(Error.UNRECOGNIZED_TYPE.code));
  }

  @Test
  void request_whenHtlBelowOne_expectNoResponseSent() throws Exception {
    // Arrange
    long uid = 456L;
    Message msg = DMT.createProbeRequest((byte) 0, uid, Type.BUILD);

    // Act
    probe.request(msg, source);

    // Assert
    verify(transport, never()).sendAsync(any(), any(), any());
  }

  @Test
  void request_whenHtlAboveMaxAndNoConnections_expectDisconnectedErrorRelayed() throws Exception {
    // Arrange
    long uid = 789L;
    Message msg = DMT.createProbeRequest((byte) (Probe.MAX_HTL + 10), uid, Type.BUILD);

    // Act
    probe.request(msg, source);

    // Assert
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport, atLeast(1)).sendAsync(captor.capture(), any(), any());
    Message sent = captor.getAllValues().getLast();
    assertThat(sent.getSpec(), is(DMT.ProbeError));
    assertThat(sent.getLong(DMT.UID), is(uid));
    assertThat(sent.getByte(DMT.TYPE), is(Error.DISCONNECTED.code));
  }

  @Test
  void request_whenExceedPerPeerAcceptance_expectOverloadErrorRelayed() throws Exception {
    // Arrange
    long uidBase = 1000L;

    // First fill the acceptance window for this source peer.
    for (int i = 0; i < 10; i++) {
      Message msg = DMT.createProbeRequest((byte) 2, uidBase + i, Type.BUILD);
      probe.request(msg, source);
    }

    // The 11th probe within the minute should be rejected with OVERLOAD.
    Message overloaded = DMT.createProbeRequest((byte) 2, uidBase + 999, Type.BUILD);

    // Act
    probe.request(overloaded, source);

    // Assert: ensure at least one ProbeError with OVERLOAD is relayed
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport, atLeast(1)).sendAsync(captor.capture(), any(), any());

    boolean sawOverload =
        captor.getAllValues().stream()
            .anyMatch(
                m ->
                    m.getSpec().equals(DMT.ProbeError)
                        && m.getByte(DMT.TYPE) == Error.OVERLOAD.code);
    assertThat("Expected an OVERLOAD error among relayed messages", sawOverload, equalTo(true));
  }

  @Test
  void start_whenNoPeers_expectListenerReceivesDisconnected() {
    // Arrange
    class RecordingListener implements Listener {
      Error error;

      @Override
      public void onError(Error error, Byte code, boolean local) {
        this.error = error;
      }

      @Override
      public void onRefused() {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onOutputBandwidth(float outputBandwidth) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onBuild(int build) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onIdentifier(long identifier, byte uptimePercentage) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onLinkLengths(float[] linkLengths) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onLocation(float location) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onStoreSize(float storeSize) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onUptime(float uptimePercentage) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onRejectStats(byte[] stats) {
        // Intentionally empty: not used in this test
      }

      @Override
      public void onOverallBulkOutputCapacity(
          byte bandwidthClassForCapacityUsage, float capacityUsage) {
        // Intentionally empty: not used in this test
      }
    }

    RecordingListener listener = new RecordingListener();

    // Act: HTL=2 so we skip local-respond path and hit routing which reports DISCONNECTED.
    probe.start((byte) 2, 4242L, Type.BUILD, listener);

    // Assert
    assertThat(listener.error, is(Error.DISCONNECTED));
  }
}

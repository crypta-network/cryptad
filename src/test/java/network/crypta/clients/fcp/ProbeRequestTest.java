package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.RandomSource;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.probe.Error;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProbeRequestTest {

  private static final long REQUEST_UID = 4242L;

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void constructor_whenTypeUnrecognized_expectMessageInvalidException() {
    SimpleFieldSet fieldSet = fieldSet("probe-1", "NO_SUCH_TYPE", "5");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ProbeRequest(fieldSet));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertTrue(exception.getMessage().contains("Unrecognized parse probe type"));
    assertTrue(exception.getMessage().contains("NO_SUCH_TYPE"));
  }

  @Test
  void constructor_whenHtlNegative_expectMessageInvalidException() {
    SimpleFieldSet fieldSet = fieldSet("probe-1", Type.BUILD, (byte) -1);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ProbeRequest(fieldSet));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals("hopsToLive cannot be negative.", exception.getMessage());
  }

  @Test
  void constructor_whenHtlNotNumber_expectMessageInvalidException() {
    SimpleFieldSet fieldSet = fieldSet("probe-1", Type.BUILD.name(), "not-a-number");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ProbeRequest(fieldSet));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertTrue(exception.getMessage().contains("Unable to parse hopsToLive"));
    assertTrue(exception.getMessage().contains("not-a-number"));
  }

  @Test
  void getFieldSet_whenCalled_returnsIndependentEmptyFieldSet() throws MessageInvalidException {
    SimpleFieldSet input = fieldSet("probe-1", Type.BUILD, (byte) 5);
    ProbeRequest request = new ProbeRequest(input);

    SimpleFieldSet result = request.getFieldSet();

    assertNotNull(result);
    assertTrue(result.isEmpty());
    assertNotSame(input, result);
  }

  @Test
  void getName_whenCalled_returnsProbeRequestConstant() throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BUILD, (byte) 5));

    assertEquals(ProbeRequest.NAME, request.getName());
  }

  @Test
  void run_whenHandlerWithoutFullAccess_expectAccessDeniedException()
      throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BUILD, (byte) 5));
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> request.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("probe-1", exception.ident);
    assertEquals("Probe requires full access.", exception.getMessage());
    verify(node, never()).startProbe(anyByte(), anyLong(), any(Type.class), any(Listener.class));
  }

  @Test
  void run_whenHtlMissing_usesProbeMaxHtl() throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BUILD, null));
    when(handler.hasFullAccess()).thenReturn(true);
    RandomSource random = mock(RandomSource.class);
    when(random.nextLong()).thenReturn(REQUEST_UID);
    when(node.getRandom()).thenReturn(random);
    ArgumentCaptor<Listener> listenerCaptor = ArgumentCaptor.forClass(Listener.class);

    request.run(handler, node);

    verify(node)
        .startProbe(eq(Probe.MAX_HTL), eq(REQUEST_UID), eq(Type.BUILD), listenerCaptor.capture());
    assertNotNull(listenerCaptor.getValue());
  }

  @Test
  void run_whenHtlProvided_usesProvidedValue() throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BUILD, (byte) 12));
    when(handler.hasFullAccess()).thenReturn(true);
    RandomSource random = mock(RandomSource.class);
    when(random.nextLong()).thenReturn(REQUEST_UID);
    when(node.getRandom()).thenReturn(random);
    ArgumentCaptor<Listener> listenerCaptor = ArgumentCaptor.forClass(Listener.class);

    request.run(handler, node);

    verify(node)
        .startProbe(eq((byte) 12), eq(REQUEST_UID), eq(Type.BUILD), listenerCaptor.capture());
    assertNotNull(listenerCaptor.getValue());
  }

  @Test
  void run_whenProbeErrors_sendsProbeError() throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BANDWIDTH, (byte) 5));
    Listener listener = runAndCaptureListener(request);
    Byte code = (byte) 7;

    listener.onError(Error.TIMEOUT, code, true);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeError.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(Error.TIMEOUT.name(), fields.get(FCPMessage.TYPE));
    assertEquals(code.byteValue(), fields.getByte(FCPMessage.CODE));
    assertTrue(fields.getBoolean(FCPMessage.LOCAL));
  }

  @Test
  void run_whenProbeRefused_sendsProbeRefused() throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet(null, Type.BANDWIDTH, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onRefused();

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeRefused.class, sent);
    assertNull(sent.getFieldSet().get(FCPMessage.IDENTIFIER));
  }

  @Test
  void run_whenProbeOutputsBandwidth_sendsProbeBandwidth()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BANDWIDTH, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onOutputBandwidth(12.5f);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeBandwidth.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(12.5d, fields.getDouble(FCPMessage.OUTPUT_BANDWIDTH), 0.0001d);
  }

  @Test
  void run_whenProbeBuildReported_sendsProbeBuild()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.BUILD, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onBuild(123456);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeBuild.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(123456, fields.getInt(FCPMessage.BUILD));
  }

  @Test
  void run_whenProbeIdentifierReported_sendsProbeIdentifier()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.IDENTIFIER, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onIdentifier(99L, (byte) 42);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeIdentifier.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(99L, fields.getLong(FCPMessage.PROBE_IDENTIFIER));
    assertEquals(42L, fields.getLong(FCPMessage.UPTIME_PERCENT));
  }

  @Test
  void run_whenProbeLinkLengthsReported_sendsProbeLinkLengths() throws MessageInvalidException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.LINK_LENGTHS, (byte) 5));
    Listener listener = runAndCaptureListener(request);
    float[] lengths = new float[] {1.25f, 2.5f, 3.75f};

    listener.onLinkLengths(lengths);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeLinkLengths.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    String[] encoded = fields.getAll(FCPMessage.LINK_LENGTHS);
    assertNotNull(encoded);
    float[] parsed = new float[encoded.length];
    for (int i = 0; i < encoded.length; i++) {
      parsed[i] = Float.parseFloat(encoded[i]);
    }
    assertArrayEquals(lengths, parsed, 0.0001f);
  }

  @Test
  void run_whenProbeLocationReported_sendsProbeLocation()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.LOCATION, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onLocation(0.75f);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeLocation.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(0.75d, fields.getDouble(FCPMessage.LOCATION), 0.0001d);
  }

  @Test
  void run_whenProbeStoreSizeReported_sendsProbeStoreSize()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.STORE_SIZE, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onStoreSize(512.5f);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeStoreSize.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(512.5d, fields.getDouble(FCPMessage.STORE_SIZE), 0.0001d);
  }

  @Test
  void run_whenProbeUptimeReported_sendsProbeUptime()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.UPTIME_7D, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onUptime(99.5f);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeUptime.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(99.5d, fields.getDouble(FCPMessage.UPTIME_PERCENT), 0.0001d);
  }

  @Test
  void run_whenProbeRejectStatsReported_sendsProbeRejectStats()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request = new ProbeRequest(fieldSet("probe-1", Type.REJECT_STATS, (byte) 5));
    Listener listener = runAndCaptureListener(request);
    byte[] stats = new byte[] {1, 2, 3, 4};

    listener.onRejectStats(stats);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeRejectStats.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(1, fields.getInt(FCPMessage.BULK_CHK_REQUEST_REJECTS));
    assertEquals(2, fields.getInt(FCPMessage.BULK_SSK_REQUEST_REJECTS));
    assertEquals(3, fields.getInt(FCPMessage.BULK_CHK_INSERT_REJECTS));
    assertEquals(4, fields.getInt(FCPMessage.BULK_SSK_INSERT_REJECTS));
  }

  @Test
  void run_whenProbeOverallBulkCapacityReported_sendsProbeOverallBulkOutputCapacityUsage()
      throws MessageInvalidException, FSParseException {
    ProbeRequest request =
        new ProbeRequest(fieldSet("probe-1", Type.OVERALL_BULK_OUTPUT_CAPACITY_USAGE, (byte) 5));
    Listener listener = runAndCaptureListener(request);

    listener.onOverallBulkOutputCapacity((byte) 3, 0.67f);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertInstanceOf(ProbeOverallBulkOutputCapacityUsage.class, sent);
    SimpleFieldSet fields = sent.getFieldSet();
    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals((byte) 3, fields.getByte(FCPMessage.OUTPUT_BANDWIDTH_CLASS));
    assertEquals(0.67d, fields.getDouble(FCPMessage.OVERALL_BULK_OUTPUT_CAPACITY_USAGE), 0.0001d);
  }

  private Listener runAndCaptureListener(ProbeRequest request) throws MessageInvalidException {
    when(handler.hasFullAccess()).thenReturn(true);
    RandomSource random = mock(RandomSource.class);
    when(random.nextLong()).thenReturn(REQUEST_UID);
    when(node.getRandom()).thenReturn(random);
    AtomicReference<Listener> listenerRef = new AtomicReference<>();
    doAnswer(
            invocation -> {
              listenerRef.set(invocation.getArgument(3));
              return null;
            })
        .when(node)
        .startProbe(anyByte(), anyLong(), any(Type.class), any(Listener.class));

    request.run(handler, node);

    return listenerRef.get();
  }

  private static SimpleFieldSet fieldSet(String identifier, Type type, Byte htl) {
    return fieldSet(
        identifier, type == null ? null : type.name(), htl == null ? null : Byte.toString(htl));
  }

  private static SimpleFieldSet fieldSet(String identifier, String typeValue, String htlValue) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    if (identifier != null) {
      fieldSet.putSingle(FCPMessage.IDENTIFIER, identifier);
    }
    if (typeValue != null) {
      fieldSet.putSingle(FCPMessage.TYPE, typeValue);
    }
    if (htlValue != null) {
      fieldSet.putSingle(FCPMessage.HTL, htlValue);
    }
    return fieldSet;
  }
}

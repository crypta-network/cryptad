package network.crypta.node;

import java.util.function.Consumer;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerLoadStatsTest {

  @Test
  void constructor_whenIntSpec_populatesFields() {
    PeerNode peer = mockPeer();
    Message message =
        mockIntMessage(
            values -> {
              values.transfersInChk = 1;
              values.transfersInSsk = 2;
              values.transfersOutChk = 3;
              values.transfersOutSsk = 4;
              values.averageTransfersOutPerInsert = 5;
              values.maxTransfersOut = 6;
              values.maxTransfersOutUpper = 7;
              values.maxTransfersOutLower = 8;
              values.maxTransfersOutPeer = 9;
              values.outputBandwidthLower = 10;
              values.outputBandwidthUpper = 11;
              values.outputBandwidthPeer = 12;
              values.inputBandwidthLower = 13;
              values.inputBandwidthUpper = 14;
              values.inputBandwidthPeer = 15;
              values.realTime = true;
            });

    PeerLoadStats stats = new PeerLoadStats(peer, message);

    assertAll(
        () -> assertEquals(peer, stats.peer),
        () -> assertEquals(1, stats.expectedTransfersInCHK),
        () -> assertEquals(2, stats.expectedTransfersInSSK),
        () -> assertEquals(3, stats.expectedTransfersOutCHK),
        () -> assertEquals(4, stats.expectedTransfersOutSSK),
        () -> assertEquals(5, stats.averageTransfersOutPerInsert),
        () -> assertEquals(6, stats.maxTransfersOut),
        () -> assertEquals(7, stats.maxTransfersOutUpperLimit),
        () -> assertEquals(8, stats.maxTransfersOutLowerLimit),
        () -> assertEquals(9, stats.maxTransfersOutPeerLimit),
        () -> assertEquals(10.0, stats.outputBandwidthLowerLimit),
        () -> assertEquals(11.0, stats.outputBandwidthUpperLimit),
        () -> assertEquals(12.0, stats.outputBandwidthPeerLimit),
        () -> assertEquals(13.0, stats.inputBandwidthLowerLimit),
        () -> assertEquals(14.0, stats.inputBandwidthUpperLimit),
        () -> assertEquals(15.0, stats.inputBandwidthPeerLimit),
        () -> assertEquals(-1, stats.totalRequests),
        () -> assertTrue(stats.realTime));
  }

  @Test
  void constructor_whenShortSpec_masksUnsignedValues() {
    PeerNode peer = mockPeer();
    Message message =
        mockShortMessage(
            values -> {
              values.transfersInChk = (short) -1;
              values.transfersInSsk = (short) -2;
              values.transfersOutChk = (short) -3;
              values.transfersOutSsk = (short) -4;
              values.averageTransfersOutPerInsert = (short) -5;
              values.maxTransfersOut = (short) -6;
              values.maxTransfersOutUpper = (short) -7;
              values.maxTransfersOutLower = (short) -8;
              values.maxTransfersOutPeer = (short) -9;
              values.outputBandwidthLower = 101;
              values.outputBandwidthUpper = 102;
              values.outputBandwidthPeer = 103;
              values.inputBandwidthLower = 104;
              values.inputBandwidthUpper = 105;
              values.inputBandwidthPeer = 106;
              values.realTime = false;
            });

    PeerLoadStats stats = new PeerLoadStats(peer, message);

    assertAll(
        () -> assertEquals(unsignedShort((short) -1), stats.expectedTransfersInCHK),
        () -> assertEquals(unsignedShort((short) -2), stats.expectedTransfersInSSK),
        () -> assertEquals(unsignedShort((short) -3), stats.expectedTransfersOutCHK),
        () -> assertEquals(unsignedShort((short) -4), stats.expectedTransfersOutSSK),
        () -> assertEquals(unsignedShort((short) -5), stats.averageTransfersOutPerInsert),
        () -> assertEquals(unsignedShort((short) -6), stats.maxTransfersOut),
        () -> assertEquals(unsignedShort((short) -7), stats.maxTransfersOutUpperLimit),
        () -> assertEquals(unsignedShort((short) -8), stats.maxTransfersOutLowerLimit),
        () -> assertEquals(unsignedShort((short) -9), stats.maxTransfersOutPeerLimit),
        () -> assertEquals(101.0, stats.outputBandwidthLowerLimit),
        () -> assertEquals(102.0, stats.outputBandwidthUpperLimit),
        () -> assertEquals(103.0, stats.outputBandwidthPeerLimit),
        () -> assertEquals(104.0, stats.inputBandwidthLowerLimit),
        () -> assertEquals(105.0, stats.inputBandwidthUpperLimit),
        () -> assertEquals(106.0, stats.inputBandwidthPeerLimit),
        () -> assertFalse(stats.realTime));
  }

  @Test
  void constructor_whenByteSpec_masksUnsignedValues() {
    PeerNode peer = mockPeer();
    Message message =
        mockByteMessage(
            values -> {
              values.transfersInChk = (byte) -1;
              values.transfersInSsk = (byte) -2;
              values.transfersOutChk = (byte) -3;
              values.transfersOutSsk = (byte) -4;
              values.averageTransfersOutPerInsert = (byte) -5;
              values.maxTransfersOut = (byte) -6;
              values.maxTransfersOutUpper = (byte) -7;
              values.maxTransfersOutLower = (byte) -8;
              values.maxTransfersOutPeer = (byte) -9;
              values.outputBandwidthLower = 201;
              values.outputBandwidthUpper = 202;
              values.outputBandwidthPeer = 203;
              values.inputBandwidthLower = 204;
              values.inputBandwidthUpper = 205;
              values.inputBandwidthPeer = 206;
              values.realTime = true;
            });

    PeerLoadStats stats = new PeerLoadStats(peer, message);

    assertAll(
        () -> assertEquals(unsignedByte((byte) -1), stats.expectedTransfersInCHK),
        () -> assertEquals(unsignedByte((byte) -2), stats.expectedTransfersInSSK),
        () -> assertEquals(unsignedByte((byte) -3), stats.expectedTransfersOutCHK),
        () -> assertEquals(unsignedByte((byte) -4), stats.expectedTransfersOutSSK),
        () -> assertEquals(unsignedByte((byte) -5), stats.averageTransfersOutPerInsert),
        () -> assertEquals(unsignedByte((byte) -6), stats.maxTransfersOut),
        () -> assertEquals(unsignedByte((byte) -7), stats.maxTransfersOutUpperLimit),
        () -> assertEquals(unsignedByte((byte) -8), stats.maxTransfersOutLowerLimit),
        () -> assertEquals(unsignedByte((byte) -9), stats.maxTransfersOutPeerLimit),
        () -> assertEquals(201.0, stats.outputBandwidthLowerLimit),
        () -> assertEquals(202.0, stats.outputBandwidthUpperLimit),
        () -> assertEquals(203.0, stats.outputBandwidthPeerLimit),
        () -> assertEquals(204.0, stats.inputBandwidthLowerLimit),
        () -> assertEquals(205.0, stats.inputBandwidthUpperLimit),
        () -> assertEquals(206.0, stats.inputBandwidthPeerLimit),
        () -> assertTrue(stats.realTime));
  }

  @Test
  void constructor_whenUnknownSpec_throwsIllegalArgumentException() {
    PeerNode peer = mockPeer();
    Message message = Mockito.mock(Message.class);
    MessageType unknownSpec = Mockito.mock(MessageType.class);
    Mockito.when(message.getSpec()).thenReturn(unknownSpec);

    assertThrows(IllegalArgumentException.class, () -> new PeerLoadStats(peer, message));
  }

  @Test
  void getOtherRunningRequests_whenInvoked_copiesPeerStats() {
    PeerNode peer = mockPeer();
    Message message =
        mockIntMessage(
            values -> {
              values.transfersInChk = 10;
              values.transfersInSsk = 11;
              values.transfersOutChk = 12;
              values.transfersOutSsk = 13;
              values.averageTransfersOutPerInsert = 14;
              values.maxTransfersOut = 15;
              values.maxTransfersOutUpper = 16;
              values.maxTransfersOutLower = 17;
              values.maxTransfersOutPeer = 18;
              values.outputBandwidthLower = 19;
              values.outputBandwidthUpper = 20;
              values.outputBandwidthPeer = 21;
              values.inputBandwidthLower = 22;
              values.inputBandwidthUpper = 23;
              values.inputBandwidthPeer = 24;
              values.realTime = false;
            });
    PeerLoadStats stats = new PeerLoadStats(peer, message);

    RunningRequestsSnapshot snapshot = stats.getOtherRunningRequests();

    assertAll(
        () -> assertEquals(stats.expectedTransfersInCHK, snapshot.expectedTransfersInCHK),
        () -> assertEquals(stats.expectedTransfersInSSK, snapshot.expectedTransfersInSSK),
        () -> assertEquals(stats.expectedTransfersOutCHK, snapshot.expectedTransfersOutCHK),
        () -> assertEquals(stats.expectedTransfersOutSSK, snapshot.expectedTransfersOutSSK),
        () -> assertEquals(stats.averageTransfersOutPerInsert, snapshot.averageTransfersPerInsert),
        () -> assertEquals(stats.totalRequests, snapshot.totalRequests),
        () -> assertEquals(0, snapshot.expectedTransfersInCHKSR),
        () -> assertEquals(0, snapshot.expectedTransfersInSSKSR),
        () -> assertEquals(0, snapshot.expectedTransfersOutCHKSR),
        () -> assertEquals(0, snapshot.expectedTransfersOutSSKSR),
        () -> assertEquals(0, snapshot.totalRequestsSR),
        () -> assertEquals(stats.realTime, snapshot.realTimeFlag));
  }

  @Test
  void equals_whenSamePeerAndFields_expectTrue() {
    PeerNode peer = mockPeer();
    Message message =
        mockIntMessage(
            values -> {
              values.transfersInChk = 1;
              values.transfersInSsk = 2;
              values.transfersOutChk = 3;
              values.transfersOutSsk = 4;
              values.averageTransfersOutPerInsert = 5;
              values.maxTransfersOut = 6;
              values.maxTransfersOutUpper = 7;
              values.maxTransfersOutLower = 8;
              values.maxTransfersOutPeer = 9;
              values.outputBandwidthLower = 10;
              values.outputBandwidthUpper = 11;
              values.outputBandwidthPeer = 12;
              values.inputBandwidthLower = 13;
              values.inputBandwidthUpper = 14;
              values.inputBandwidthPeer = 15;
              values.realTime = true;
            });

    PeerLoadStats first = new PeerLoadStats(peer, message);
    PeerLoadStats second = new PeerLoadStats(peer, message);

    assertAll(
        () -> assertEquals(first, second), () -> assertEquals(peer.hashCode(), first.hashCode()));
  }

  @Test
  void equals_whenDifferentPeer_expectFalse() {
    Message message = mockIntMessage();
    PeerLoadStats first = new PeerLoadStats(mockPeer(), message);
    PeerLoadStats second = new PeerLoadStats(mockPeer(), message);

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenDifferentFields_expectFalse() {
    PeerNode peer = mockPeer();
    PeerLoadStats base =
        new PeerLoadStats(peer, mockIntMessage(values -> values.transfersInChk = 1));
    PeerLoadStats changed =
        new PeerLoadStats(peer, mockIntMessage(values -> values.transfersInChk = 2));

    assertNotEquals(base, changed);
  }

  @Test
  @SuppressWarnings("AssertBetweenInconvertibleTypes")
  void equals_whenOtherType_expectFalse() {
    PeerLoadStats stats = new PeerLoadStats(mockPeer(), mockIntMessage());

    assertNotEquals("not-stats", stats);
  }

  @ParameterizedTest
  @CsvSource({"true, 30.0", "false, 12.0"})
  void peerLimit_whenInputFlagSpecified_returnsExpectedValue(boolean input, double expected) {
    PeerLoadStats stats =
        new PeerLoadStats(
            mockPeer(),
            mockIntMessage(
                values -> {
                  values.outputBandwidthPeer = 12;
                  values.inputBandwidthPeer = 30;
                }));

    assertEquals(expected, stats.peerLimit(input));
  }

  @ParameterizedTest
  @CsvSource({"true, 40.0", "false, 10.0"})
  void lowerLimit_whenInputFlagSpecified_returnsExpectedValue(boolean input, double expected) {
    PeerLoadStats stats =
        new PeerLoadStats(
            mockPeer(),
            mockIntMessage(
                values -> {
                  values.outputBandwidthLower = 10;
                  values.inputBandwidthLower = 40;
                }));

    assertEquals(expected, stats.lowerLimit(input));
  }

  @Test
  void toString_whenCalled_formatsAllFields() {
    PeerNode peer = mockPeerWithName();
    Message message =
        mockIntMessage(
            values -> {
              values.transfersInChk = 1;
              values.transfersInSsk = 2;
              values.transfersOutChk = 3;
              values.transfersOutSsk = 4;
              values.averageTransfersOutPerInsert = 5;
              values.maxTransfersOut = 6;
              values.maxTransfersOutUpper = 7;
              values.maxTransfersOutLower = 8;
              values.maxTransfersOutPeer = 9;
              values.outputBandwidthLower = 10;
              values.outputBandwidthUpper = 11;
              values.outputBandwidthPeer = 12;
              values.inputBandwidthLower = 13;
              values.inputBandwidthUpper = 14;
              values.inputBandwidthPeer = 15;
              values.realTime = true;
            });
    PeerLoadStats stats = new PeerLoadStats(peer, message);

    String text = stats.toString();

    assertEquals(
        "peer-string:output:{lower=10.0,upper=11.0,this=12.0},input:lower=13.0,upper=14.0,peer=15.0},requests:in:1chk/2ssk:out:3chk/4ssk"
            + " transfers=6/9/8/7",
        text);
  }

  private PeerNode mockPeer() {
    return Mockito.mock(PeerNode.class);
  }

  private PeerNode mockPeerWithName() {
    PeerNode peer = Mockito.mock(PeerNode.class);
    Mockito.when(peer.toString()).thenReturn("peer-string");
    return peer;
  }

  private static final class IntMessageValues {
    private int transfersInChk = 1;
    private int transfersInSsk = 2;
    private int transfersOutChk = 3;
    private int transfersOutSsk = 4;
    private int averageTransfersOutPerInsert = 5;
    private int maxTransfersOut = 6;
    private int maxTransfersOutUpper = 7;
    private int maxTransfersOutLower = 8;
    private int maxTransfersOutPeer = 9;
    private int outputBandwidthLower = 10;
    private int outputBandwidthUpper = 11;
    private int outputBandwidthPeer = 12;
    private int inputBandwidthLower = 13;
    private int inputBandwidthUpper = 14;
    private int inputBandwidthPeer = 15;
    private boolean realTime = true;
  }

  private static final class ShortMessageValues {
    private short transfersInChk = 1;
    private short transfersInSsk = 2;
    private short transfersOutChk = 3;
    private short transfersOutSsk = 4;
    private short averageTransfersOutPerInsert = 5;
    private short maxTransfersOut = 6;
    private short maxTransfersOutUpper = 7;
    private short maxTransfersOutLower = 8;
    private short maxTransfersOutPeer = 9;
    private int outputBandwidthLower = 10;
    private int outputBandwidthUpper = 11;
    private int outputBandwidthPeer = 12;
    private int inputBandwidthLower = 13;
    private int inputBandwidthUpper = 14;
    private int inputBandwidthPeer = 15;
    private boolean realTime = true;
  }

  private static final class ByteMessageValues {
    private byte transfersInChk = 1;
    private byte transfersInSsk = 2;
    private byte transfersOutChk = 3;
    private byte transfersOutSsk = 4;
    private byte averageTransfersOutPerInsert = 5;
    private byte maxTransfersOut = 6;
    private byte maxTransfersOutUpper = 7;
    private byte maxTransfersOutLower = 8;
    private byte maxTransfersOutPeer = 9;
    private int outputBandwidthLower = 10;
    private int outputBandwidthUpper = 11;
    private int outputBandwidthPeer = 12;
    private int inputBandwidthLower = 13;
    private int inputBandwidthUpper = 14;
    private int inputBandwidthPeer = 15;
    private boolean realTime = true;
  }

  private Message mockIntMessage() {
    return mockIntMessage(_ -> {});
  }

  private Message mockIntMessage(Consumer<IntMessageValues> configure) {
    IntMessageValues values = new IntMessageValues();
    configure.accept(values);
    Message message = Mockito.mock(Message.class);
    Mockito.when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusInt);
    Mockito.when(message.getInt(DMT.OTHER_TRANSFERS_IN_CHK)).thenReturn(values.transfersInChk);
    Mockito.when(message.getInt(DMT.OTHER_TRANSFERS_IN_SSK)).thenReturn(values.transfersInSsk);
    Mockito.when(message.getInt(DMT.OTHER_TRANSFERS_OUT_CHK)).thenReturn(values.transfersOutChk);
    Mockito.when(message.getInt(DMT.OTHER_TRANSFERS_OUT_SSK)).thenReturn(values.transfersOutSsk);
    Mockito.when(message.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT))
        .thenReturn(values.averageTransfersOutPerInsert);
    Mockito.when(message.getInt(DMT.MAX_TRANSFERS_OUT)).thenReturn(values.maxTransfersOut);
    Mockito.when(message.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT))
        .thenReturn(values.maxTransfersOutUpper);
    Mockito.when(message.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT))
        .thenReturn(values.maxTransfersOutLower);
    Mockito.when(message.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT))
        .thenReturn(values.maxTransfersOutPeer);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.outputBandwidthLower);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.outputBandwidthUpper);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.outputBandwidthPeer);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.inputBandwidthLower);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.inputBandwidthUpper);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.inputBandwidthPeer);
    Mockito.when(message.getBoolean(DMT.REAL_TIME_FLAG)).thenReturn(values.realTime);
    return message;
  }

  private Message mockShortMessage(Consumer<ShortMessageValues> configure) {
    ShortMessageValues values = new ShortMessageValues();
    configure.accept(values);
    Message message = Mockito.mock(Message.class);
    Mockito.when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusShort);
    Mockito.when(message.getShort(DMT.OTHER_TRANSFERS_IN_CHK)).thenReturn(values.transfersInChk);
    Mockito.when(message.getShort(DMT.OTHER_TRANSFERS_IN_SSK)).thenReturn(values.transfersInSsk);
    Mockito.when(message.getShort(DMT.OTHER_TRANSFERS_OUT_CHK)).thenReturn(values.transfersOutChk);
    Mockito.when(message.getShort(DMT.OTHER_TRANSFERS_OUT_SSK)).thenReturn(values.transfersOutSsk);
    Mockito.when(message.getShort(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT))
        .thenReturn(values.averageTransfersOutPerInsert);
    Mockito.when(message.getShort(DMT.MAX_TRANSFERS_OUT)).thenReturn(values.maxTransfersOut);
    Mockito.when(message.getShort(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT))
        .thenReturn(values.maxTransfersOutUpper);
    Mockito.when(message.getShort(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT))
        .thenReturn(values.maxTransfersOutLower);
    Mockito.when(message.getShort(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT))
        .thenReturn(values.maxTransfersOutPeer);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.outputBandwidthLower);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.outputBandwidthUpper);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.outputBandwidthPeer);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.inputBandwidthLower);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.inputBandwidthUpper);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.inputBandwidthPeer);
    Mockito.when(message.getBoolean(DMT.REAL_TIME_FLAG)).thenReturn(values.realTime);
    return message;
  }

  private Message mockByteMessage(Consumer<ByteMessageValues> configure) {
    ByteMessageValues values = new ByteMessageValues();
    configure.accept(values);
    Message message = Mockito.mock(Message.class);
    Mockito.when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusByte);
    Mockito.when(message.getByte(DMT.OTHER_TRANSFERS_IN_CHK)).thenReturn(values.transfersInChk);
    Mockito.when(message.getByte(DMT.OTHER_TRANSFERS_IN_SSK)).thenReturn(values.transfersInSsk);
    Mockito.when(message.getByte(DMT.OTHER_TRANSFERS_OUT_CHK)).thenReturn(values.transfersOutChk);
    Mockito.when(message.getByte(DMT.OTHER_TRANSFERS_OUT_SSK)).thenReturn(values.transfersOutSsk);
    Mockito.when(message.getByte(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT))
        .thenReturn(values.averageTransfersOutPerInsert);
    Mockito.when(message.getByte(DMT.MAX_TRANSFERS_OUT)).thenReturn(values.maxTransfersOut);
    Mockito.when(message.getByte(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT))
        .thenReturn(values.maxTransfersOutUpper);
    Mockito.when(message.getByte(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT))
        .thenReturn(values.maxTransfersOutLower);
    Mockito.when(message.getByte(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT))
        .thenReturn(values.maxTransfersOutPeer);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.outputBandwidthLower);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.outputBandwidthUpper);
    Mockito.when(message.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.outputBandwidthPeer);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT))
        .thenReturn(values.inputBandwidthLower);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT))
        .thenReturn(values.inputBandwidthUpper);
    Mockito.when(message.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT))
        .thenReturn(values.inputBandwidthPeer);
    Mockito.when(message.getBoolean(DMT.REAL_TIME_FLAG)).thenReturn(values.realTime);
    return message;
  }

  private int unsignedShort(short value) {
    return value & 0xFFFF;
  }

  private int unsignedByte(byte value) {
    return value & 0xFF;
  }
}

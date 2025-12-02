package com.onionnetworks.fec;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class Native16CodeTest {

  private static final class StubNative16Code extends Native16Code {
    int encodeCalls;
    int decodeCalls;
    int freeCalls;
    int newFecCalls;

    byte[][] lastSrc;
    int[] lastSrcOff;
    byte[][] lastRepair;
    int[] lastRepairOff;
    int[] lastEncodeIndex;
    int lastEncodePacketLength;

    byte[][] lastPkts;
    int[] lastPktsOff;
    int[] lastDecodeIndex;
    int lastDecodePacketLength;

    StubNative16Code(int k, int n) {
      super(k, n);
    }

    @Override
    protected void nativeEncode(
        byte[][] src,
        int[] srcOff,
        int[] index,
        byte[][] repair,
        int[] repairOff,
        int k,
        int packetLength) {
      encodeCalls++;
      lastSrc = src;
      lastSrcOff = srcOff;
      lastRepair = repair;
      lastRepairOff = repairOff;
      lastEncodeIndex = index.clone();
      lastEncodePacketLength = packetLength;
    }

    @Override
    protected void nativeDecode(
        byte[][] pkts, int[] pktsOff, int[] index, int k, int packetLength) {
      decodeCalls++;
      lastPkts = pkts.clone();
      lastPktsOff = pktsOff.clone();
      lastDecodeIndex = index.clone();
      lastDecodePacketLength = packetLength;
    }

    @Override
    protected synchronized long nativeNewFEC(int k, int n) {
      newFecCalls++;
      return 42L;
    }

    @Override
    protected synchronized void nativeFreeFEC() {
      freeCalls++;
    }
  }

  @Test
  void constructor_whenInvoked_callsNativeNewFEC() {
    StubNative16Code code = new StubNative16Code(2, 3);

    assertEquals(1, code.newFecCalls);
    assertEquals("Native16Code[k=2,n=3]", code.toString());
    code.close();
  }

  @Test
  void encode_whenPacketLengthOdd_throwsIllegalArgumentException() {
    StubNative16Code code = new StubNative16Code(2, 3);

    byte[][] src = new byte[][] {{1, 2}, {3, 4}};
    int[] srcOff = new int[] {0, 0};
    byte[][] repair = new byte[][] {{0, 0}};
    int[] repairOff = new int[] {0};
    int[] index = new int[] {2};

    assertThrows(
        IllegalArgumentException.class,
        () -> code.encode(src, srcOff, repair, repairOff, index, 3));
    assertEquals(0, code.encodeCalls);
    code.close();
  }

  @Test
  void encode_whenPacketLengthEven_invokesNativeEncodeWithArguments() {
    StubNative16Code code = new StubNative16Code(2, 3);

    byte[][] src = new byte[][] {{1, 2, 3, 4}, {5, 6, 7, 8}};
    int[] srcOff = new int[] {1, 2};
    byte[][] repair = new byte[][] {{0, 0, 0, 0}};
    int[] repairOff = new int[] {0};
    int[] index = new int[] {2};

    code.encode(src, srcOff, repair, repairOff, index, 4);

    assertEquals(1, code.encodeCalls);
    assertSame(src, code.lastSrc);
    assertSame(srcOff, code.lastSrcOff);
    assertSame(repair, code.lastRepair);
    assertSame(repairOff, code.lastRepairOff);
    assertArrayEquals(index, code.lastEncodeIndex);
    assertEquals(4, code.lastEncodePacketLength);
    code.close();
  }

  @Test
  void decode_whenPacketLengthOdd_throwsIllegalArgumentException() {
    StubNative16Code code = new StubNative16Code(3, 5);

    byte[][] pkts = new byte[][] {{1, 2}, {3, 4}, {5, 6}};
    int[] pktsOff = new int[] {0, 0, 0};
    int[] index = new int[] {0, 1, 2};

    assertThrows(IllegalArgumentException.class, () -> code.decode(pkts, pktsOff, index, 5, true));
    assertEquals(0, code.decodeCalls);
    code.close();
  }

  @Test
  void decode_whenNotInOrder_shufflesBeforeNativeDecode() {
    StubNative16Code code = new StubNative16Code(3, 5);

    byte[] pkt0 = new byte[] {0, 0, 0, 0};
    byte[] pkt1 = new byte[] {1, 1, 1, 1};
    byte[] pkt2 = new byte[] {2, 2, 2, 2};

    byte[][] pkts = new byte[][] {pkt0, pkt1, pkt2};
    int[] pktsOff = new int[] {5, 10, 15};
    int[] index = new int[] {2, 0, 1};

    code.decode(pkts, pktsOff, index, 4, false);

    assertEquals(1, code.decodeCalls);
    assertSame(pkt1, pkts[0]);
    assertSame(pkt2, pkts[1]);
    assertSame(pkt0, pkts[2]);
    assertArrayEquals(new int[] {10, 15, 5}, pktsOff);
    assertArrayEquals(new int[] {0, 1, 2}, index);
    assertSame(pkt1, code.lastPkts[0]);
    assertSame(pkt2, code.lastPkts[1]);
    assertSame(pkt0, code.lastPkts[2]);
    assertArrayEquals(new int[] {10, 15, 5}, code.lastPktsOff);
    assertArrayEquals(new int[] {0, 1, 2}, code.lastDecodeIndex);
    assertEquals(4, code.lastDecodePacketLength);
    code.close();
  }

  @Test
  void close_whenCalledMultipleTimes_invokesNativeFreeOnlyOnce() {
    StubNative16Code code = new StubNative16Code(2, 3);

    code.close();
    code.close();

    assertEquals(1, code.freeCalls);
  }
}

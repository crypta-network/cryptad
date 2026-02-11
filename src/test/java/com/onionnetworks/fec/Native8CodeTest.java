package com.onionnetworks.fec;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class Native8CodeTest {

  private static final class StubNative8Code extends Native8Code {
    int encodeCalls;
    int decodeCalls;
    int freeCalls;
    int newFecCalls;
    volatile boolean throwOnFree;

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

    StubNative8Code(int k, int n) {
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
      return 99L;
    }

    @Override
    protected synchronized void nativeFreeFEC() {
      freeCalls++;
      if (throwOnFree) {
        throw new RuntimeException("boom");
      }
    }
  }

  @Test
  void constructor_whenInvoked_callsNativeNewFECAndBuildsToString() {
    StubNative8Code code = new StubNative8Code(2, 4);

    assertEquals(1, code.newFecCalls);
    assertEquals("Native8Code[k=2,n=4]", code.toString());
    code.close();
  }

  @Test
  void encode_whenInvokedForwardsAllArguments() {
    StubNative8Code code = new StubNative8Code(3, 5);

    byte[][] src = new byte[][] {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    int[] srcOff = new int[] {0, 1, 2};
    byte[][] repair = new byte[][] {{0, 0, 0}, {0, 0, 0}};
    int[] repairOff = new int[] {1, 2};
    int[] index = new int[] {3, 4};

    code.encode(src, srcOff, repair, repairOff, index, 3);

    assertEquals(1, code.encodeCalls);
    assertSame(src, code.lastSrc);
    assertSame(srcOff, code.lastSrcOff);
    assertSame(repair, code.lastRepair);
    assertSame(repairOff, code.lastRepairOff);
    assertArrayEquals(index, code.lastEncodeIndex);
    assertEquals(3, code.lastEncodePacketLength);
    code.close();
  }

  @Test
  void decode_whenNotInOrder_shufflesBeforeCallingNativeDecode() {
    StubNative8Code code = new StubNative8Code(3, 5);

    byte[] pkt0 = new byte[] {0, 0, 0};
    byte[] pkt1 = new byte[] {1, 1, 1};
    byte[] pkt2 = new byte[] {2, 2, 2};

    byte[][] pkts = new byte[][] {pkt0, pkt1, pkt2};
    int[] pktsOff = new int[] {10, 20, 30};
    int[] index = new int[] {2, 0, 1};

    code.decode(pkts, pktsOff, index, 3, false);

    assertEquals(1, code.decodeCalls);
    assertSame(pkt1, pkts[0]);
    assertSame(pkt2, pkts[1]);
    assertSame(pkt0, pkts[2]);
    assertArrayEquals(new int[] {20, 30, 10}, pktsOff);
    assertArrayEquals(new int[] {0, 1, 2}, index);
    assertSame(pkt1, code.lastPkts[0]);
    assertSame(pkt2, code.lastPkts[1]);
    assertSame(pkt0, code.lastPkts[2]);
    assertArrayEquals(new int[] {20, 30, 10}, code.lastPktsOff);
    assertArrayEquals(new int[] {0, 1, 2}, code.lastDecodeIndex);
    assertEquals(3, code.lastDecodePacketLength);
    code.close();
  }

  @Test
  void decode_whenAlreadyInOrder_passesThroughWithoutShuffle() {
    StubNative8Code code = new StubNative8Code(2, 4);

    byte[] pkt0 = new byte[] {9, 9, 9};
    byte[] pkt1 = new byte[] {8, 8, 8};
    byte[][] pkts = new byte[][] {pkt0, pkt1};
    int[] pktsOff = new int[] {0, 4};
    int[] index = new int[] {0, 1};

    code.decode(pkts, pktsOff, index, 3, true);

    assertEquals(1, code.decodeCalls);
    assertSame(pkt0, code.lastPkts[0]);
    assertSame(pkt1, code.lastPkts[1]);
    assertArrayEquals(new int[] {0, 4}, code.lastPktsOff);
    assertArrayEquals(new int[] {0, 1}, code.lastDecodeIndex);
    assertArrayEquals(new byte[][] {pkt0, pkt1}, pkts);
    code.close();
  }

  @Test
  void close_whenCalledMultipleTimes_invokesNativeFreeOnlyOnce() {
    StubNative8Code code = new StubNative8Code(4, 6);

    code.close();
    code.close();

    assertEquals(1, code.freeCalls);
  }

  @Test
  void close_whenNativeFreeThrows_marksClosedAndPreventsSubsequentCalls() throws Exception {
    StubNative8Code code = new StubNative8Code(1, 2);
    code.throwOnFree = true;

    RuntimeException thrown = assertThrows(RuntimeException.class, code::close);
    assertEquals("boom", thrown.getMessage());
    assertTrue(isClosed(code));

    code.close();

    assertEquals(1, code.freeCalls);
  }

  private static boolean isClosed(Native8Code code) throws Exception {
    Field closed = Native8Code.class.getDeclaredField("closed");
    closed.setAccessible(true);
    return closed.getBoolean(code);
  }
}

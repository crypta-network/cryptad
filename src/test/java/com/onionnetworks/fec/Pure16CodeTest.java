package com.onionnetworks.fec;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class Pure16CodeTest {

  private static final int K = 3;
  private static final int N = 5;

  @Test
  void encode_withOddPacketLength_expectIllegalArgumentException() {
    try (Pure16Code code = new Pure16Code(2, 3)) {
      byte[][] src = new byte[][] {new byte[3], new byte[3]};
      int[] srcOff = new int[] {0, 0};
      byte[][] repair = new byte[][] {new byte[3]};
      int[] repairOff = new int[] {0};
      int[] index = new int[] {2};

      assertThrows(
          IllegalArgumentException.class,
          () -> code.encode(src, srcOff, repair, repairOff, index, 3));
    }
  }

  @Test
  void decode_withOddPacketLength_expectIllegalArgumentException() {
    try (Pure16Code code = new Pure16Code(2, 3)) {
      byte[][] pkts = new byte[][] {new byte[3], new byte[3]};
      int[] pktsOff = new int[] {0, 0};
      int[] index = new int[] {0, 2};

      assertThrows(
          IllegalArgumentException.class, () -> code.decode(pkts, pktsOff, index, 3, true));
    }
  }

  @Test
  void encode_withSystematicIndex_copiesUsingOffsets() {
    try (Pure16Code code = new Pure16Code(2, 3)) {
      byte[] srcPacket = new byte[] {99, 1, 2, 3, 4, 5};
      byte[][] src = new byte[][] {srcPacket, new byte[6]};
      int[] srcOff = new int[] {1, 0};

      byte[] repairPacket = new byte[] {77, 0, 0, 0, 0, 0};
      byte[][] repair = new byte[][] {repairPacket};
      int[] repairOff = new int[] {1};
      int[] index = new int[] {0};

      code.encode(src, srcOff, repair, repairOff, index, 4);

      assertEquals(77, repairPacket[0]);
      assertArrayEquals(new byte[] {1, 2, 3, 4}, Arrays.copyOfRange(repairPacket, 1, 5));
      assertEquals(0, repairPacket[5]);
      assertArrayEquals(new byte[] {99, 1, 2, 3, 4, 5}, srcPacket);
    }
  }

  @Test
  void decode_withRepairPacket_recoversMissingDataAndReorders() {
    try (Pure16Code code = new Pure16Code(K, N)) {
      byte[][] src =
          new byte[][] {
            new byte[] {0x01, 0x23, 0x45, 0x67},
            new byte[] {(byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF},
            new byte[] {0x10, 0x32, 0x54, 0x76}
          };
      int[] srcOff = new int[] {0, 0, 0};

      byte[][] repair = new byte[][] {new byte[4], new byte[4]};
      int[] repairOff = new int[] {0, 0};
      int[] repairIndex = new int[] {3, 4};

      code.encode(src, srcOff, repair, repairOff, repairIndex, 4);

      byte[][] pkts = new byte[][] {src[1], src[0], repair[0]};
      int[] pktsOff = new int[] {0, 0, 0};
      int[] index = new int[] {1, 0, 3};

      code.decode(pkts, pktsOff, index, 4, false);

      assertArrayEquals(src[0], pkts[0]);
      assertArrayEquals(src[1], pkts[1]);
      assertArrayEquals(src[2], pkts[2]);
      assertArrayEquals(new int[] {0, 1, 2}, index);
    }
  }

  @Test
  void toString_returnsReadableSummary() {
    try (Pure16Code code = new Pure16Code(K, N)) {
      assertEquals("Pure16Code[k=3,n=5]", code.toString());
    }
  }
}

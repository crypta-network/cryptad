package com.onionnetworks.fec;

import com.onionnetworks.util.Buffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PureCodeTest {

  private static final int K = 3;
  private static final int N = 5;

  @Test
  void encode_withSystematicIndex_copiesUsingOffsets() {
    try (PureCode code = new PureCode(2, 3)) {
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
  void encode_withRepairIndex_overwritesExistingDataWithGaloisProduct() {
    try (PureCode code = new PureCode(K, N)) {
      byte[][] src =
          new byte[][] {
            new byte[] {1, 1, 1, 1},
            new byte[] {0, 0, 0, 0},
            new byte[] {0, 0, 0, 0}
          };
      int[] srcOff = new int[] {0, 0, 0};

      byte[] repairPacket = new byte[] {11, 0x55, 0x55, 0x55, 0x55, 99};
      byte[][] repair = new byte[][] {repairPacket};
      int[] repairOff = new int[] {1};
      int repairIndex = 3; // first parity packet when k=3

      code.encode(src, srcOff, repair, repairOff, new int[] {repairIndex}, 4);

      int matrixPos = repairIndex * code.k;
      int expectedValue = code.encMatrix[matrixPos] & 0xFF;

      for (int i = 1; i <= 4; i++) {
        assertEquals(expectedValue, Byte.toUnsignedInt(repairPacket[i]));
      }
      assertEquals(11, repairPacket[0]);
      assertEquals(99, repairPacket[5]);
    }
  }

  @Test
  void decode_withRepairPacket_recoversMissingDataAndReorders() {
    try (PureCode code = new PureCode(K, N)) {
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
  void decode_withDuplicateIndexes_throwsIllegalArgumentException() {
    try (PureCode code = new PureCode(2, 3)) {
      byte[][] pkts = new byte[][] {new byte[2], new byte[2]};
      int[] pktsOff = new int[] {0, 0};
      int[] index = new int[] {1, 1};

      IllegalArgumentException ex =
          assertThrows(
              IllegalArgumentException.class, () -> code.decode(pkts, pktsOff, index, 2, false));

      assertTrue(ex.getMessage().contains("Shuffle error"));
    }
  }

  @Test
  void decode_withBuffers_preservesBufferOrderWhileRecovering() {
    try (PureCode code = new PureCode(K, N)) {
      Buffer[] buffers =
          new Buffer[] {
            new Buffer(new byte[] {9, 8, 7, 6}),
            new Buffer(new byte[] {5, 4, 3, 2}),
            new Buffer(new byte[] {1, 1, 1, 1})
          };

      Buffer[] repairs = new Buffer[] {new Buffer(4)};
      int[] repairIndex = new int[] {3};

      code.encode(buffers, repairs, repairIndex);

      Buffer[] received = new Buffer[] {buffers[0], repairs[0], buffers[2]};
      int[] index = new int[] {0, 3, 2};

      code.decode(received, index);

      assertArrayEquals(new byte[] {9, 8, 7, 6}, received[0].b);
      assertArrayEquals(new byte[] {5, 4, 3, 2}, received[1].b);
      assertArrayEquals(new byte[] {1, 1, 1, 1}, received[2].b);
      assertArrayEquals(new int[] {0, 1, 2}, index);
    }
  }

  @Test
  void toString_returnsReadableSummary() {
    try (PureCode code = new PureCode(K, N)) {
      assertEquals("PureCode[k=3,n=5]", code.toString());
    }
  }
}

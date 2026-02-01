package network.crypta.client;

import static org.junit.jupiter.api.Assertions.*;

import com.onionnetworks.fec.FECCode;
import com.onionnetworks.fec.FECCodeFactory;
import com.onionnetworks.fec.FECMath;
import com.onionnetworks.fec.PureCode;
import com.onionnetworks.util.Buffer;
import com.onionnetworks.util.Util;
import network.crypta.support.TestProperty;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class CodeTest {

  public static final int KK = 192;
  public static final int PACKET_SIZE = 4096;
  public static FECMath fecMath = new FECMath(8);

  @Test
  void benchmark_whenBenchmarkEnabled_doesNotThrow() {
    Assumptions.assumeTrue(TestProperty.BENCHMARK, "Benchmark tests are disabled");

    // Arrange
    int lim = fecMath.getGfSize() + 1;

    // Act
    Executable benchmark =
        () -> {
          try (FECCode maybeNative = FECCodeFactory.getDefault().createFECCode(KK, lim);
              FECCode pureCode = new PureCode(KK, lim)) {
            int[] index = new int[KK];

            for (int i = 0; i < KK; i++) {
              index[i] = lim - i - 1;
            }

            byte[] src = new byte[KK * PACKET_SIZE];
            Util.getRand().nextBytes(src);
            Buffer[] srcBufs = createBuffers(src);

            byte[] repair = new byte[KK * PACKET_SIZE];
            Buffer[] repairBufs = createBuffers(repair);

            int[] indexBackup = new int[index.length];
            System.arraycopy(index, 0, indexBackup, 0, index.length);

            System.out.println("Getting ready for benchmarking encode()");
            long t1 = System.currentTimeMillis();
            maybeNative.encode(srcBufs, repairBufs, index);
            long t2 = System.currentTimeMillis();
            pureCode.encode(srcBufs, repairBufs, indexBackup);
            long t3 = System.currentTimeMillis();

            float dNativeEncode = t2 - t1;
            float dPureEncode = t3 - t2;

            Buffer[] repairBufs2 = repairBufs.clone();
            System.arraycopy(repairBufs, 0, repairBufs2, 0, repairBufs.length);
            System.out.println("Getting ready for benchmarking decode()");
            t1 = System.currentTimeMillis();
            maybeNative.decode(repairBufs, index);
            t2 = System.currentTimeMillis();
            pureCode.decode(repairBufs2, indexBackup);
            t3 = System.currentTimeMillis();

            float dNativeDecode = t2 - t1;
            float dPureDecode = t3 - t2;

            System.out.println(maybeNative);
            System.out.println(pureCode);
            System.out.println(
                "Native code took "
                    + dNativeEncode
                    + "ms whereas java's code took "
                    + dPureEncode
                    + "ms to encode()");
            System.out.println(
                "Native code took "
                    + dNativeDecode
                    + "ms whereas java's code took "
                    + dPureDecode
                    + "ms to decode()");
          }
        };

    // Assert
    assertDoesNotThrow(benchmark);
  }

  @Test
  void encodeDecode_whenIndexReversedFromGfSize_roundTripsData() {
    // Arrange
    int lim = fecMath.getGfSize() + 1;
    try (FECCode code = FECCodeFactory.getDefault().createFECCode(KK, lim);
        FECCode code2 = new PureCode(KK, lim)) {
      int[] index = new int[KK];

      for (int i = 0; i < KK; i++) {
        index[i] = lim - i - 1;
      }

      // Act
      EncodeDecodeResult nativeThenPure = encodeDecode(code, code2, index);
      EncodeDecodeResult pureThenNative = encodeDecode(code2, code, index);

      // Assert
      assertArrayEquals(nativeThenPure.original(), nativeThenPure.decoded());
      assertArrayEquals(pureThenNative.original(), pureThenNative.decoded());
    }
  }

  @Test
  void encodeDecode_whenIndexReversedFromKk_roundTripsData() {
    // Arrange
    int lim = fecMath.getGfSize() + 1;
    try (FECCode code = FECCodeFactory.getDefault().createFECCode(KK, lim);
        FECCode code2 = new PureCode(KK, lim)) {
      int[] index = new int[KK];

      for (int i = 0; i < KK; i++) {
        index[i] = KK - i;
      }

      // Act
      EncodeDecodeResult nativeThenPure = encodeDecode(code, code2, index);
      EncodeDecodeResult pureThenNative = encodeDecode(code2, code, index);

      // Assert
      assertArrayEquals(nativeThenPure.original(), nativeThenPure.decoded());
      assertArrayEquals(pureThenNative.original(), pureThenNative.decoded());
    }
  }

  @Test
  void encodeDecode_whenShiftedIndexOrder_roundTripsData() {
    // Arrange
    int lim = fecMath.getGfSize() + 1;
    try (FECCode code = FECCodeFactory.getDefault().createFECCode(KK, lim);
        FECCode code2 = new PureCode(KK, lim)) {
      int[] index = new int[KK];

      int maxI0 = KK / 2;
      if (maxI0 + KK > lim) {
        maxI0 = lim - KK;
      }

      for (int s = maxI0 - 2; s <= maxI0; s++) {
        for (int i = 0; i < KK; i++) {
          index[i] = i + s;
        }

        // Act
        EncodeDecodeResult nativeThenPure = encodeDecode(code, code2, index);
        EncodeDecodeResult pureThenNative = encodeDecode(code2, code, index);

        // Assert
        assertArrayEquals(nativeThenPure.original(), nativeThenPure.decoded());
        assertArrayEquals(pureThenNative.original(), pureThenNative.decoded());
      }
    }
  }

  /**
   * Encodes random packet data and decodes it using the provided codes and index.
   *
   * @return a result containing the original and decoded data for comparison
   */
  private static EncodeDecodeResult encodeDecode(FECCode encode, FECCode decode, int[] index) {
    byte[] src = new byte[KK * PACKET_SIZE];
    Util.getRand().nextBytes(src);
    Buffer[] srcBufs = createBuffers(src);

    byte[] repair = new byte[KK * PACKET_SIZE];
    Buffer[] repairBufs = createBuffers(repair);

    encode.encode(srcBufs, repairBufs, index);
    decode.decode(repairBufs, index);

    return new EncodeDecodeResult(src, repair);
  }

  private static final class EncodeDecodeResult {
    private final byte[] original;
    private final byte[] decoded;

    private EncodeDecodeResult(byte[] original, byte[] decoded) {
      this.original = original;
      this.decoded = decoded;
    }

    private byte[] original() {
      return original;
    }

    private byte[] decoded() {
      return decoded;
    }
  }

  private static Buffer[] createBuffers(byte[] src) {
    Buffer[] srcBufs = new Buffer[KK];
    for (int i = 0; i < srcBufs.length; i++) {
      srcBufs[i] = new Buffer(src, i * PACKET_SIZE, PACKET_SIZE);
    }
    return srcBufs;
  }
}

package network.crypta.crypt;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.crypto.params.DSAParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GlobalTest {

  // ---------- truncateHash ----------

  @Test
  void truncateHash_whenNull_throwsNPE() {
    assertThrows(NullPointerException.class, () -> Global.truncateHash(null));
  }

  @Test
  void truncateHash_whenEmpty_returnsZeroByte() {
    byte[] out = Global.truncateHash(new byte[0]);
    assertArrayEquals(new byte[] {0}, out);
  }

  @Test
  void truncateHash_whenAllOnes256_returns255BitMask() {
    byte[] in = new byte[32];
    Arrays.fill(in, (byte) 0xFF);

    byte[] out = Global.truncateHash(in);

    byte[] expected = new byte[32];
    expected[0] = 0x7F; // clear the top (256th) bit
    Arrays.fill(expected, 1, expected.length, (byte) 0xFF);

    assertArrayEquals(expected, out);
    BigInteger outVal = new BigInteger(1, out);
    BigInteger mask = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE);
    assertEquals(mask, outVal);
  }

  @Test
  void truncateHash_whenOnlyTopBitSet_returnsZero() {
    byte[] in = new byte[32];
    in[0] = (byte) 0x80; // only the highest bit is set (bit 255)

    byte[] out = Global.truncateHash(in);

    assertArrayEquals(new byte[] {0}, out);
  }

  @Test
  void truncateHash_whenAlreadyUnder255bits_returnsInputUnchanged() {
    byte[] in = new byte[32];
    in[0] = 0x01; // value < 2^255, with the sign bit clear in the first byte

    byte[] out = Global.truncateHash(in);

    assertArrayEquals(in, out);
  }

  @Test
  void truncateHash_whenLongInput_reducesWithin255Bits() {
    byte[] in = new byte[64];
    Arrays.fill(in, (byte) 0xA5); // arbitrary non‑trivial pattern

    BigInteger inputVal = new BigInteger(1, in);
    BigInteger mask = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE);
    BigInteger expectedVal = inputVal.and(mask);

    byte[] out = Global.truncateHash(in);
    BigInteger outVal = new BigInteger(1, out);

    assertEquals(expectedVal, outVal);
    assertTrue(out.length <= 32, "Truncated hash must fit within 255 bits (<= 32 bytes)");
    if (out.length > 0) {
      assertEquals(0, (out[0] & 0x80), "Top bit must be clear after truncation");
    }
  }

  // ---------- getDSAgroupBigAParameters ----------

  @Test
  void getDSAgroupBigAParameters_returnsMatchingValues() {
    DSAParameters params = Global.getDSAgroupBigAParameters();
    assertNotNull(params);
    assertEquals(Global.DSAgroupBigA.getP(), params.getP());
    assertEquals(Global.DSAgroupBigA.getQ(), params.getQ());
    assertEquals(Global.DSAgroupBigA.getG(), params.getG());
  }

  @Test
  void DSAgroupBigA_hasExpectedBitLengthsAndPositivity() {
    BigInteger p = Global.DSAgroupBigA.getP();
    BigInteger q = Global.DSAgroupBigA.getQ();
    BigInteger g = Global.DSAgroupBigA.getG();

    assertEquals(2048, p.bitLength(), "p must be a 2048‑bit prime modulus");
    assertTrue(q.signum() > 0 && g.signum() > 0, "q and g must be positive");
  }
}

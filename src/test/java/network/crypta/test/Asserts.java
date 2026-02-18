package network.crypta.test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public abstract class Asserts {

  private Asserts() {}

  public static void assertArrayEquals(byte[] expecteds, byte[] actuals) {
    if (!Arrays.equals(expecteds, actuals)) {
      fail(
          "expected:<"
              + Arrays.toString(expecteds)
              + "> but was:<"
              + Arrays.toString(actuals)
              + ">");
    }
  }
}

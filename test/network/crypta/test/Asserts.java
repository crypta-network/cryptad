package network.crypta.test;

import static org.junit.Assert.*;

import java.util.Arrays;

public abstract class Asserts {

	private Asserts() {}

	public static void assertArrayEquals(byte[] expecteds, byte[] actuals) {
		if (!Arrays.equals(expecteds, actuals)) {
			fail("expected:<" + Arrays.toString(expecteds) +
			  "> but was:<" + Arrays.toString(actuals) + ">");
		}
	}

}

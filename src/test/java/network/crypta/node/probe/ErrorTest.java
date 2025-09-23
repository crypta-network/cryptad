package network.crypta.node.probe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.HashSet;
import org.junit.Test;

/** Tests conversion from code and code validity. */
public class ErrorTest {

  @Test
  public void testValidCodes() {
    for (Error t : Error.values()) {
      final byte code = t.code;
      if (Type.isValid(code)) {
        try {
          Error error = Error.valueOf(code);
          // Code of enum should match.
          assertEquals(error.code, code);
        } catch (IllegalArgumentException e) {
          // Should not throw - was determined to be valid.
          fail("valueOf() threw when given valid code " + code + ". (" + t.name() + ")");
        }
      } else {
        fail("isValid() returned false for valid code " + code + ". (" + t.name() + ")");
      }
    }
  }

  @Test
  public void testInvalidCodes() {
    HashSet<Byte> validCodes = new HashSet<>();
    for (Error error : Error.values()) {
      validCodes.add(error.code);
    }

    for (byte code = Byte.MIN_VALUE; code <= Byte.MAX_VALUE; code++) {
      if (validCodes.contains(code)) continue;

      if (Error.isValid(code)) {
        fail("isValid() returned true for invalid code " + code + ".");
      }
      if (code == Byte.MAX_VALUE) return;
    }
  }
}

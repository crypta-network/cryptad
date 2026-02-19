package network.crypta.support.compress;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class LzmaInputStreamTest {
  @Test
  void classIsLoadable() {
    assertNotNull(LzmaInputStream.class);
  }
}

package network.crypta.crypt;

import java.security.SecureRandom;
import network.crypta.runtime.bootstrap.NodeStarter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings("java:S100")
class CryptoRandomsTest {
  @Test
  void shared_whenCalledTwice_expectSameInstance() {
    SecureRandom first = CryptoRandoms.shared();
    SecureRandom second = CryptoRandoms.shared();

    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void shared_whenComparedWithNodeStarter_expectSameInstance() {
    assertSame(CryptoRandoms.shared(), NodeStarter.getGlobalSecureRandom());
  }
}

package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class RealNodePingTestTest {
  @Test
  @SuppressWarnings("java:S3415")
  void constants_whenRead_expectConsecutivePorts() {
    assertEquals(RealNodeBusyNetworkTest.DARKNET_PORT_END, RealNodePingTest.DARKNET_PORT1);
    assertEquals(RealNodePingTest.DARKNET_PORT1 + 1, RealNodePingTest.DARKNET_PORT2);
    assertEquals(RealNodePingTest.DARKNET_PORT2 + 1, RealNodePingTest.DARKNET_PORT_END);
  }

  @Test
  void constants_whenRead_expectTrustAndVisibilityDefaults() {
    assertEquals(FRIEND_TRUST.LOW, RealNodePingTest.trust);
    assertEquals(FRIEND_VISIBILITY.NO, RealNodePingTest.visibility);
  }

  @Test
  void main_whenReflected_expectPublicStaticVoidSignature() throws Exception {
    Method main = RealNodePingTest.class.getDeclaredMethod("main");

    int modifiers = main.getModifiers();
    assertFalse(Modifier.isPublic(modifiers));
    assertTrue(Modifier.isStatic(modifiers));
    assertEquals(void.class, main.getReturnType());
    assertArrayEquals(new Class<?>[0], main.getParameterTypes());
  }
}

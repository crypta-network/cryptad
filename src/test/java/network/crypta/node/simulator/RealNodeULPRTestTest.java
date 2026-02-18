package network.crypta.node.simulator;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.NodeInitException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S3415"})
class RealNodeULPRTestTest {

  @Test
  void constants_whenRead_expectPortRangeAndCountsAligned() {
    assertEquals(RealNodePingTest.DARKNET_PORT_END, RealNodeULPRTest.DARKNET_PORT_BASE);
    assertEquals(
        RealNodeULPRTest.DARKNET_PORT_BASE + RealNodeULPRTest.NUMBER_OF_NODES,
        RealNodeULPRTest.DARKNET_PORT_END);
    assertEquals(10, RealNodeULPRTest.NUMBER_OF_NODES);
  }

  @Test
  void constants_whenRead_expectExitCodesDerivedFromNodeInitBase() {
    assertEquals(NodeInitException.EXIT_NODE_UPPER_LIMIT, RealNodeULPRTest.EXIT_BASE);
    assertEquals(RealNodeULPRTest.EXIT_BASE + 1, RealNodeULPRTest.EXIT_KEY_EXISTS);
    assertEquals(
        RealNodeULPRTest.EXIT_BASE + 2, RealNodeULPRTest.EXIT_UNKNOWN_ERROR_CHECKING_KEY_NOT_EXIST);
    assertEquals(RealNodeULPRTest.EXIT_BASE + 4, RealNodeULPRTest.EXIT_TEST_FAILED);
  }

  @Test
  void constants_whenRead_expectRuntimeFlagsAndPeerDefaults() {
    assertEquals(FRIEND_TRUST.LOW, RealNodeULPRTest.trust);
    assertEquals(FRIEND_VISIBILITY.NO, RealNodeULPRTest.visibility);
    assertTrue(RealNodeULPRTest.ENABLE_SWAPPING);
    assertTrue(RealNodeULPRTest.ENABLE_ULPRS);
    assertTrue(RealNodeULPRTest.ENABLE_PER_NODE_FAILURE_TABLES);
    assertTrue(RealNodeULPRTest.ENABLE_FOAF);
    assertEquals((short) 10, RealNodeULPRTest.MAX_HTL);
    assertEquals(100, RealNodeULPRTest.NUMBER_OF_TESTS);
  }

  @Test
  void main_whenReflected_expectPublicStaticVoidSignature() throws Exception {
    Method main = RealNodeULPRTest.class.getDeclaredMethod("main");

    int modifiers = main.getModifiers();
    assertTrue(Modifier.isPublic(modifiers));
    assertTrue(Modifier.isStatic(modifiers));
    assertEquals(void.class, main.getReturnType());
    assertArrayEquals(new Class<?>[0], main.getParameterTypes());
  }
}

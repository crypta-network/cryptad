package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.RequestStarter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FcpProtocolDefaultsParityTest {

  @Test
  void priorityConstants_whenComparedToRequestStarter_matchDaemonValues() {
    assertEquals(
        RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, FcpPriorityClasses.IMMEDIATE_SPLITFILE);
    assertEquals(RequestStarter.PREFETCH_PRIORITY_CLASS, FcpPriorityClasses.PREFETCH);
    assertEquals(RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, FcpPriorityClasses.BULK_SPLITFILE);
    assertEquals(RequestStarter.MAXIMUM_PRIORITY_CLASS, FcpPriorityClasses.MAXIMUM);
    assertEquals(RequestStarter.PAUSED_PRIORITY_CLASS, FcpPriorityClasses.PAUSED);
  }

  @Test
  void insertDefaults_whenComparedToNode_matchDaemonValues() {
    assertEquals(Node.FORK_ON_CACHEABLE_DEFAULT, FcpInsertDefaults.FORK_ON_CACHEABLE_DEFAULT);
  }

  @Test
  void peerNoteTypes_whenComparedToNode_matchDaemonValues() {
    assertEquals(
        Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT, FcpPeerNoteTypes.PRIVATE_DARKNET_COMMENT);
  }

  @Test
  void isValid_whenCheckingBoundaryValues_matchesRequestStarterBehavior() {
    short belowMinimum = (short) (FcpPriorityClasses.MAXIMUM - 1);
    short aboveMaximum = (short) (FcpPriorityClasses.PAUSED + 1);
    short inRange = FcpPriorityClasses.IMMEDIATE_SPLITFILE;

    assertFalse(FcpPriorityClasses.isValid(belowMinimum));
    assertTrue(FcpPriorityClasses.isValid(FcpPriorityClasses.MAXIMUM));
    assertTrue(FcpPriorityClasses.isValid(inRange));
    assertTrue(FcpPriorityClasses.isValid(FcpPriorityClasses.PAUSED));
    assertFalse(FcpPriorityClasses.isValid(aboveMaximum));

    assertEquals(
        RequestStarter.isValidPriorityClass(belowMinimum),
        FcpPriorityClasses.isValid(belowMinimum));
    assertEquals(
        RequestStarter.isValidPriorityClass(FcpPriorityClasses.MAXIMUM),
        FcpPriorityClasses.isValid(FcpPriorityClasses.MAXIMUM));
    assertEquals(RequestStarter.isValidPriorityClass(inRange), FcpPriorityClasses.isValid(inRange));
    assertEquals(
        RequestStarter.isValidPriorityClass(FcpPriorityClasses.PAUSED),
        FcpPriorityClasses.isValid(FcpPriorityClasses.PAUSED));
    assertEquals(
        RequestStarter.isValidPriorityClass(aboveMaximum),
        FcpPriorityClasses.isValid(aboveMaximum));
  }
}

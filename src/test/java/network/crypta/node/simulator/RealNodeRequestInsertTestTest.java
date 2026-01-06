package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.KeyBlock;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeClientCoreTransfers;
import network.crypta.node.RequestTracker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RealNodeRequestInsertTestTest {

  @Test
  void insertRequestTest_whenFetchReturnsMatchingData_expectExitZeroOnTarget() throws Exception {
    NodeClientCore insertCore = mock(NodeClientCore.class);
    NodeClientCore fetchCore = mock(NodeClientCore.class);
    NodeClientCoreTransfers insertTransfers = mock(NodeClientCoreTransfers.class);
    NodeClientCoreTransfers fetchTransfers = mock(NodeClientCoreTransfers.class);
    when(insertCore.getTransfers()).thenReturn(insertTransfers);
    when(fetchCore.getTransfers()).thenReturn(fetchTransfers);

    Node insertNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node fetchNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(insertNode.services().clientCore()).thenReturn(insertCore);
    when(fetchNode.services().clientCore()).thenReturn(fetchCore);

    Node[] nodes = createNodes(null, insertNode, fetchNode);
    DummyRandomSource random = new SequenceRandom(0, 1);

    RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 1);

    when(fetchTransfers.realGetKey(
            any(ClientKey.class), eq(false), eq(false), eq(false), eq(false)))
        .thenAnswer(
            invocation -> {
              ClientKey key = invocation.getArgument(0);
              ClientKeyBlock returnedBlock = mock(ClientKeyBlock.class);
              String docName = key.getURI().getDocName();
              when(returnedBlock.memoryDecode())
                  .thenReturn(docName.getBytes(StandardCharsets.UTF_8));
              return returnedBlock;
            });

    int result = tester.insertRequestTest();

    assertEquals(0, result);
    verify(insertTransfers)
        .realPut(
            any(KeyBlock.class),
            eq(false),
            eq(RealNodeRequestInsertTest.FORK_ON_CACHEABLE),
            eq(false),
            eq(false),
            eq(RealNodeRequestInsertTest.REAL_TIME_FLAG));
    verify(fetchTransfers)
        .realGetKey(any(ClientKey.class), eq(false), eq(false), eq(false), eq(false));
  }

  @Test
  void insertRequestTest_whenInsertThrowsException_expectInsertFailedExitCode() throws Exception {
    NodeClientCore insertCore = mock(NodeClientCore.class);
    NodeClientCoreTransfers insertTransfers = mock(NodeClientCoreTransfers.class);
    when(insertCore.getTransfers()).thenReturn(insertTransfers);
    doThrow(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR))
        .when(insertTransfers)
        .realPut(
            any(KeyBlock.class),
            eq(false),
            eq(RealNodeRequestInsertTest.FORK_ON_CACHEABLE),
            eq(false),
            eq(false),
            eq(RealNodeRequestInsertTest.REAL_TIME_FLAG));

    Node insertNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(insertNode.services().clientCore()).thenReturn(insertCore);

    Node[] nodes =
        createNodes(null, insertNode, mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS));
    DummyRandomSource random = new SequenceRandom(0, 1);

    RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 1);

    int result = tester.insertRequestTest();

    assertEquals(RealNodeTest.EXIT_INSERT_FAILED, result);
  }

  @Test
  void insertRequestTest_whenFetchThrowsException_expectContinue() throws Exception {
    RequestTracker tracker = mock(RequestTracker.class);
    when(tracker.getTotalRunningUIDsAlt()).thenReturn(0);

    NodeClientCore insertCore = mock(NodeClientCore.class);
    NodeClientCore fetchCore = mock(NodeClientCore.class);
    NodeClientCoreTransfers insertTransfers = mock(NodeClientCoreTransfers.class);
    NodeClientCoreTransfers fetchTransfers = mock(NodeClientCoreTransfers.class);
    when(insertCore.getTransfers()).thenReturn(insertTransfers);
    when(fetchCore.getTransfers()).thenReturn(fetchTransfers);
    when(fetchTransfers.realGetKey(
            any(ClientKey.class), eq(false), eq(false), eq(false), eq(false)))
        .thenThrow(new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND));

    Node insertNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node fetchNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(insertNode.services().clientCore()).thenReturn(insertCore);
    when(fetchNode.services().clientCore()).thenReturn(fetchCore);

    Node[] nodes = createNodes(tracker, insertNode, fetchNode);
    DummyRandomSource random = new SequenceRandom(0, 1);

    RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 1);

    int result = tester.insertRequestTest();

    assertEquals(-1, result);
    verify(insertTransfers)
        .realPut(
            any(KeyBlock.class),
            eq(false),
            eq(RealNodeRequestInsertTest.FORK_ON_CACHEABLE),
            eq(false),
            eq(false),
            eq(RealNodeRequestInsertTest.REAL_TIME_FLAG));
  }

  @Test
  void insertRequestTest_whenFetchReturnsMismatchedData_expectBadDataExitCode() throws Exception {
    NodeClientCore insertCore = mock(NodeClientCore.class);
    NodeClientCore fetchCore = mock(NodeClientCore.class);
    NodeClientCoreTransfers insertTransfers = mock(NodeClientCoreTransfers.class);
    NodeClientCoreTransfers fetchTransfers = mock(NodeClientCoreTransfers.class);
    when(insertCore.getTransfers()).thenReturn(insertTransfers);
    when(fetchCore.getTransfers()).thenReturn(fetchTransfers);

    ClientKeyBlock returnedBlock = mock(ClientKeyBlock.class);
    when(returnedBlock.memoryDecode()).thenReturn("mismatch".getBytes(StandardCharsets.UTF_8));
    when(fetchTransfers.realGetKey(
            any(ClientKey.class), eq(false), eq(false), eq(false), eq(false)))
        .thenReturn(returnedBlock);

    Node insertNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Node fetchNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(insertNode.services().clientCore()).thenReturn(insertCore);
    when(fetchNode.services().clientCore()).thenReturn(fetchCore);

    Node[] nodes = createNodes(null, insertNode, fetchNode);
    DummyRandomSource random = new SequenceRandom(0, 1);

    RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 1);

    int result = tester.insertRequestTest();

    assertEquals(RealNodeTest.EXIT_BAD_DATA, result);
  }

  private static Node[] createNodes(RequestTracker tracker, Node insertNode, Node fetchNode) {
    Node[] nodes = new Node[RealNodeRequestInsertTest.NUMBER_OF_NODES];
    for (int i = 0; i < nodes.length; i++) {
      nodes[i] = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    }
    nodes[0] = insertNode;
    nodes[1] = fetchNode;
    if (tracker != null) {
      for (Node node : nodes) {
        when(node.routing().tracker()).thenReturn(tracker);
      }
    }
    return nodes;
  }

  private static final class SequenceRandom extends DummyRandomSource {
    private final int[] sequence;
    private int index;

    private SequenceRandom(int... sequence) {
      super(0L);
      this.sequence = sequence.clone();
    }

    @Override
    public int nextInt(int bound) {
      int value = sequence[index % sequence.length];
      index++;
      return Math.floorMod(value, bound);
    }
  }
}

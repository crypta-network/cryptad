package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ExpectedDataLengthTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @ParameterizedTest
  @CsvSource({"identifier-1,true,42", "another-id,false,0"})
  void getFieldSet_whenCalledWithDifferentInputs_expectMatchingValues(
      String identifier, boolean global, long dataLength) {
    ExpectedDataLength message = new ExpectedDataLength(identifier, global, dataLength);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(identifier, fieldSet.get("Identifier"));
    assertEquals(Boolean.toString(global), fieldSet.get("Global"));
    assertEquals(Long.toString(dataLength), fieldSet.get("DataLength"));
  }

  @Test
  void getFieldSet_whenMutatingReturnedInstance_expectSubsequentCallsUnaffected() {
    ExpectedDataLength message = new ExpectedDataLength("initial", false, 1024);

    SimpleFieldSet detachedFieldSet = message.getFieldSet();
    detachedFieldSet.putOverwrite("Identifier", "tampered");

    SimpleFieldSet freshFieldSet = message.getFieldSet();

    assertEquals("initial", freshFieldSet.get("Identifier"));
    assertEquals("false", freshFieldSet.get("Global"));
    assertEquals("1024", freshFieldSet.get("DataLength"));
  }

  @Test
  void getName_whenCalled_expectExpectedDataLength() {
    ExpectedDataLength message = new ExpectedDataLength("id", true, 1);

    assertEquals("ExpectedDataLength", message.getName());
  }

  @Test
  void run_whenCalled_expectNoInteractions() {
    ExpectedDataLength message = new ExpectedDataLength("identifier", true, 2048);

    assertDoesNotThrow(() -> message.run(handler, node));
    verifyNoInteractions(handler, node);
  }
}

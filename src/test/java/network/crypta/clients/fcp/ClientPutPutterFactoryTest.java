package network.crypta.clients.fcp;

import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ClientPutPutterFactoryTest {
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  @Test
  void create_whenExecutionSpecProvided_delegatesToRuntimeSupport() throws Exception {
    ClientPutCallback callback = mock(ClientPutCallback.class);
    RequestClient requestClient = mock(RequestClient.class);
    when(callback.getRequestClient()).thenReturn(requestClient);
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);
    ClientPutExecution execution = mock(ClientPutExecution.class);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI(VALID_CHK),
            "identifier",
            0,
            (short) 3,
            ClientRequest.Persistence.CONNECTION,
            false,
            "token",
            false);
    ClientPutExecutionSpec executionSpec =
        new ClientPutExecutionSpec(
            callback,
            requestParams,
            new InsertContext(InsertContextOptions.builder().build()),
            new ArrayBucket(),
            new ClientMetadata("text/plain"),
            true,
            new ClientPutExecutionSpec.ExecutionOptions(
                "file.txt", true, new byte[] {1, 2, 3}, 42L));
    when(runtimeSupport.createSingleFileExecution(executionSpec)).thenReturn(execution);

    ClientPutExecution actual = ClientPutPutterFactory.create(runtimeSupport, executionSpec);

    assertSame(execution, actual);
    verify(runtimeSupport).createSingleFileExecution(executionSpec);
  }
}

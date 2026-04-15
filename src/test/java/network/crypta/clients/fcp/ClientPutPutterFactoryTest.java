package network.crypta.clients.fcp;

import network.crypta.client.ClientMetadata;
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
    FcpInsertCallback callback = mock(FcpInsertCallback.class);
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
            new DefaultFcpInsertContextHandle(
                new FcpInsertContextLimits(0, 0, 0),
                new FcpInsertOptions(
                    new FcpInsertBehaviorOptions(false, false, false, 0, false, false, false),
                    new FcpInsertTuningOptions(
                        false, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
                    null)),
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

package network.crypta.clients.fcp;

import java.io.IOException;

/**
 * Creates opaque single-file insert execution handles for FCP requests.
 *
 * <p>The adapter builds a detached execution spec and asks the runtime bridge to translate it into
 * a live inserter. This keeps the concrete daemon client-engine types out of {@code :adapter-fcp}
 * while preserving the existing request assembly flow.
 */
final class ClientPutPutterFactory {
  private ClientPutPutterFactory() {}

  static ClientPutExecution create(
      FcpInsertRuntimeSupport runtimeSupport, ClientPutExecutionSpec executionSpec)
      throws IOException {
    return runtimeSupport.createSingleFileExecution(executionSpec);
  }
}

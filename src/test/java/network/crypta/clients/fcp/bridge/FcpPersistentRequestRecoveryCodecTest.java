package network.crypta.clients.fcp.bridge;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.RequestIdentifier;
import network.crypta.crypt.ChecksumChecker;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

@SuppressWarnings("java:S100")
class FcpPersistentRequestRecoveryCodecTest {

  @Test
  void restartFrom_whenCalled_expectDelegatesToClientRequestUsingConvertedIdentifier()
      throws Exception {
    // Arrange
    FcpPersistentRequestRecoveryCodec codec = new FcpPersistentRequestRecoveryCodec();
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[0]));
    PersistentRequestIdentifier persistentIdentifier =
        new PersistentRequestIdentifier(
            false, "client-a", "request-1", PersistentRequestIdentifier.RequestType.PUTDIR);
    RequestIdentifier requestIdentifier =
        RequestIdentifier.fromPersistentRequestIdentifier(persistentIdentifier);
    ClientContext context = mock(ClientContext.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientRequest expectedRequest = mock(ClientRequest.class);

    // Act
    try (MockedStatic<ClientRequest> clientRequestMock = mockStatic(ClientRequest.class)) {
      clientRequestMock
          .when(
              () ->
                  ClientRequest.restartFrom(
                      same(dis), eq(requestIdentifier), same(context), same(checker)))
          .thenReturn(expectedRequest);

      PersistentRequestHandle restored =
          codec.restartFrom(dis, persistentIdentifier, context, checker);

      // Assert
      assertSame(expectedRequest, restored);
      clientRequestMock.verify(
          () ->
              ClientRequest.restartFrom(
                  same(dis), eq(requestIdentifier), same(context), same(checker)));
    }
  }
}

package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;
import network.crypta.client.async.InsertRequestParams;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutPutterFactoryTest {
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  @Test
  void create_whenValidInput_returnsConfiguredPutter() throws Exception {
    ClientPutCallback callback = mock(ClientPutCallback.class);
    RequestClient requestClient = mock(RequestClient.class);
    when(callback.getRequestClient()).thenReturn(requestClient);

    ClientMetadata metadata = new ClientMetadata("text/plain");
    ArrayBucket data = new ArrayBucket();
    FreenetURI targetUri = new FreenetURI(VALID_CHK);
    InsertContext insertContext = new InsertContext(InsertContextOptions.builder().build());
    ClientPutterRequest request =
        new ClientPutterRequest(
            new InsertRequestParams(callback, targetUri, insertContext, (short) 3),
            data,
            metadata,
            true);
    byte[] overrideCrypto = new byte[] {1, 2, 3};
    ClientPutterOptions options = new ClientPutterOptions("file.txt", true, overrideCrypto, 42L);

    ClientPutter putter = ClientPutPutterFactory.create(request, options);

    assertNotNull(putter);
    assertSame(callback, getField(putter, "callback"));
    assertSame(data, getField(putter, "data"));
    assertSame(targetUri, getField(putter, "targetURI"));
    assertSame(metadata, getField(putter, "cm"));
    assertSame(insertContext, getField(putter, "ctx"));
    assertEquals("file.txt", getField(putter, "targetFilename"));
    assertTrue((Boolean) getField(putter, "binaryBlob"));
    assertSame(overrideCrypto, getField(putter, "overrideSplitfileCrypto"));
    assertEquals(42L, getField(putter, "metadataThreshold"));
    assertTrue((Boolean) getField(putter, "isMetadata"));
  }

  private static Object getField(ClientPutter putter, String name) throws Exception {
    Field field = ClientPutter.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(putter);
  }
}

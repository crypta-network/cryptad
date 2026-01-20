package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.reflect.Field;
import network.crypta.client.FetchContext;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetStatusSnapshotBuilderTest {

  @Test
  void persistentTagMessage_whenDiskReturnType_expectFieldSetContainsDiskFilenameAndValues()
      throws Exception {
    // Arrange
    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    when(fetchContext.getMaxNonSplitfileRetries()).thenReturn(7);
    when(fetchContext.getMaxOutputLength()).thenReturn(12_345L);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(true);
    File targetFile = new File("target.bin");
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.getGlobalForeverClient();
    ClientGet request =
        newRequest(
            FreenetURI.EMPTY_CHK_URI,
            "id-1",
            11,
            (short) 3,
            Persistence.FOREVER,
            "token",
            true,
            client,
            ReturnType.DISK,
            targetFile,
            true,
            fetchContext,
            requestClient);
    ClientGetStatusSnapshotBuilder builder = new ClientGetStatusSnapshotBuilder(request);

    // Act
    FCPMessage message = builder.persistentTagMessage();

    // Assert
    SimpleFieldSet fieldSet = message.getFieldSet();
    assertEquals("id-1", fieldSet.get("Identifier"));
    assertEquals(FreenetURI.EMPTY_CHK_URI.toString(false, false), fieldSet.get("URI"));
    assertEquals("disk", fieldSet.get("ReturnType"));
    assertEquals("forever", fieldSet.get("Persistence"));
    assertEquals(targetFile.getAbsolutePath(), fieldSet.get("Filename"));
    assertEquals(11, fieldSet.getInt("Verbosity", -1));
    assertEquals(3, fieldSet.getInt("PriorityClass", -1));
    assertEquals("token", fieldSet.get("ClientToken"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertTrue(fieldSet.getBoolean("Started", false));
    assertEquals(7, fieldSet.getInt("MaxRetries", -1));
    assertTrue(fieldSet.getBoolean("BinaryBlob", false));
    assertEquals(12_345L, fieldSet.getLong("MaxSize", -1L));
    assertTrue(fieldSet.getBoolean("RealTime", false));
  }

  @Test
  void persistentTagMessage_whenClientTokenNull_expectFieldSetOmitsClientTokenAndFilename()
      throws Exception {
    // Arrange
    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    when(fetchContext.getMaxNonSplitfileRetries()).thenReturn(1);
    when(fetchContext.getMaxOutputLength()).thenReturn(42L);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(false);
    PersistentRequestClient client =
        new PersistentRequestClient("client", null, false, null, Persistence.REBOOT, null);
    ClientGet request =
        newRequest(
            FreenetURI.EMPTY_CHK_URI,
            "id-2",
            2,
            (short) 1,
            Persistence.REBOOT,
            null,
            false,
            client,
            ReturnType.DIRECT,
            null,
            false,
            fetchContext,
            requestClient);
    ClientGetStatusSnapshotBuilder builder = new ClientGetStatusSnapshotBuilder(request);

    // Act
    FCPMessage message = builder.persistentTagMessage();

    // Assert
    SimpleFieldSet fieldSet = message.getFieldSet();
    assertNull(fieldSet.get("ClientToken"));
    assertNull(fieldSet.get("Filename"));
    assertEquals("direct", fieldSet.get("ReturnType"));
    assertFalse(fieldSet.getBoolean("Global", true));
    assertFalse(fieldSet.getBoolean("Started", true));
    assertEquals(1, fieldSet.getInt("MaxRetries", -1));
    assertFalse(fieldSet.getBoolean("BinaryBlob", true));
    assertEquals(42L, fieldSet.getLong("MaxSize", -1L));
    assertFalse(fieldSet.getBoolean("RealTime", true));
  }

  @Test
  void persistentTagMessage_whenUriNull_expectThrowsNullPointerException() throws Exception {
    // Arrange
    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    when(fetchContext.getMaxNonSplitfileRetries()).thenReturn(1);
    when(fetchContext.getMaxOutputLength()).thenReturn(1L);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(false);
    PersistentRequestClient client =
        new PersistentRequestClient("client", null, true, null, Persistence.REBOOT, null);
    ClientGet request =
        newRequest(
            null,
            "id-3",
            1,
            (short) 1,
            Persistence.REBOOT,
            "token",
            false,
            client,
            ReturnType.NONE,
            null,
            false,
            fetchContext,
            requestClient);
    ClientGetStatusSnapshotBuilder builder = new ClientGetStatusSnapshotBuilder(request);

    // Act + Assert
    assertThrows(NullPointerException.class, builder::persistentTagMessage);
  }

  private static ClientGet newRequest(
      FreenetURI uri,
      String identifier,
      int verbosity,
      short priorityClass,
      Persistence persistence,
      String clientToken,
      boolean started,
      PersistentRequestClient client,
      ReturnType returnType,
      File targetFile,
      boolean binaryBlob,
      FetchContext fetchContext,
      RequestClient requestClient)
      throws Exception {
    ClientGet request = new ClientGet();
    setField(request, "uri", uri);
    setField(request, "identifier", identifier);
    setField(request, "verbosity", verbosity);
    setField(request, "priorityClass", priorityClass);
    setField(request, "persistence", persistence);
    setField(request, "clientToken", clientToken);
    setField(request, "started", started);
    setField(request, "client", client);
    setField(request, "returnType", returnType);
    setField(request, "targetFile", targetFile);
    setField(request, "binaryBlob", binaryBlob);
    setField(request, "fctx", fetchContext);
    setField(request, "lowLevelClient", requestClient);
    return request;
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = null;
    Class<?> type = target.getClass();
    while (type != null && field == null) {
      try {
        field = type.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        type = type.getSuperclass();
      }
    }
    if (field == null) {
      throw new NoSuchFieldException(fieldName);
    }
    field.setAccessible(true);
    field.set(target, value);
  }
}

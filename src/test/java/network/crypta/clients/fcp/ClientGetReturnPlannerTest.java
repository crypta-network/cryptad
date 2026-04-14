package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetReturnPlannerTest {
  private static final String VALID_URI =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String PAYLOAD_BIN = "payload.bin";
  private static final String REQUEST_ID = "id";

  @Mock private TransferAccessPort transferAccess;
  @Mock private FCPConnectionHandler handler;
  @Mock private DdaAccessController ddaAccessController;

  @TempDir Path tempDir;

  @Test
  void constructor_whenIdentifierNull_throwsNullPointerException() {
    ClientGetFetchConfig fetchConfig = newFetchConfig(false);

    assertThrows(
        NullPointerException.class, () -> new ClientGetReturnPlanner(null, false, fetchConfig));
  }

  @Test
  void constructor_whenFetchContextNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> new ClientGetReturnPlanner(REQUEST_ID, false, null));
  }

  @Test
  void forGlobalRequest_whenReturnTypeNotDisk_returnsEmptySetup() throws Exception {
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));

    ClientGetReturnPlanner.ReturnSetup setup =
        planner.forGlobalRequest(ReturnType.DIRECT, null, false, transferAccess);

    assertAll(
        () -> assertNull(setup.bucket()),
        () -> assertNull(setup.targetFile()),
        () -> assertNull(setup.extension()));
    verifyNoInteractions(transferAccess);
  }

  @Test
  void forGlobalRequest_whenDiskNotAllowed_throwsNotAllowedException() {
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));
    File target = tempDir.resolve(PAYLOAD_BIN).toFile();
    when(transferAccess.allowDownloadTo(target)).thenReturn(false);

    assertThrows(
        NotAllowedException.class,
        () -> planner.forGlobalRequest(ReturnType.DISK, target, false, transferAccess));

    verify(transferAccess).allowDownloadTo(target);
  }

  @Test
  void forGlobalRequest_whenDiskAndZeroLengthFile_deletesAndReturnsSetup() throws Exception {
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));
    File target = tempDir.resolve(PAYLOAD_BIN).toFile();
    assertTrue(target.createNewFile());
    when(transferAccess.allowDownloadTo(target)).thenReturn(true);

    ClientGetReturnPlanner.ReturnSetup setup =
        planner.forGlobalRequest(ReturnType.DISK, target, true, transferAccess);

    assertAll(
        () -> assertInstanceOf(FileBucket.class, setup.bucket()),
        () -> assertEquals(target, setup.targetFile()),
        () -> assertEquals("bin", setup.extension()),
        () -> assertFalse(target.exists()));
  }

  @Test
  void forGlobalRequest_whenDiskAndExistingNonZeroFile_throwsIOException() throws Exception {
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    Files.writeString(targetPath, "data");
    File target = targetPath.toFile();
    when(transferAccess.allowDownloadTo(target)).thenReturn(true);

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> planner.forGlobalRequest(ReturnType.DISK, target, false, transferAccess));

    assertTrue(thrown.getMessage().contains("Target filename exists already"));
    assertTrue(target.exists());
  }

  @Test
  void forMessage_whenReturnTypeNotDisk_returnsEmptySetup() throws Exception {
    ClientGetMessage message = buildMessage(ReturnType.NONE, null);
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));

    ClientGetReturnPlanner.ReturnSetup setup = planner.forMessage(message, transferAccess, handler);

    assertAll(
        () -> assertNull(setup.bucket()),
        () -> assertNull(setup.targetFile()),
        () -> assertNull(setup.extension()));
    verifyNoInteractions(transferAccess, handler);
  }

  @Test
  void forMessage_whenDownloadNotAllowed_throwsMessageInvalidException() throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, true, newFetchConfig(false));
    when(transferAccess.allowDownloadTo(targetPath.toFile())).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class,
            () -> planner.forMessage(message, transferAccess, handler));

    assertAll(
        () -> assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode),
        () -> assertEquals(REQUEST_ID, thrown.ident),
        () -> assertTrue(thrown.global));
  }

  @Test
  void forMessage_whenDdaDenied_throwsMessageInvalidException() throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));
    when(transferAccess.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class,
            () -> planner.forMessage(message, transferAccess, handler));

    assertEquals(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, thrown.protocolCode);
  }

  @Test
  void forMessage_whenExistingNonZeroFile_throwsMessageInvalidExceptionWithCause()
      throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    Files.writeString(targetPath, "data");
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(false));
    when(transferAccess.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(true);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class,
            () -> planner.forMessage(message, transferAccess, handler));

    assertAll(
        () -> assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, thrown.protocolCode),
        () -> assertNotNull(thrown.getCause()),
        () -> assertInstanceOf(IOException.class, thrown.getCause()));
  }

  @Test
  void forMessage_whenAllowedAndFilterDataTrue_returnsSetupWithExtension() throws Exception {
    Path targetPath = tempDir.resolve("payload.txt");
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner =
        new ClientGetReturnPlanner(REQUEST_ID, false, newFetchConfig(true));
    when(transferAccess.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(true);

    ClientGetReturnPlanner.ReturnSetup setup = planner.forMessage(message, transferAccess, handler);

    assertAll(
        () -> assertInstanceOf(FileBucket.class, setup.bucket()),
        () -> assertEquals(targetPath.toFile(), setup.targetFile()),
        () -> assertEquals("txt", setup.extension()));
  }

  private static ClientGetFetchConfig newFetchConfig(boolean filterData) {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setFilterData(filterData);
    return fetchConfig;
  }

  private ClientGetMessage buildMessage(ReturnType type, File diskFile)
      throws MessageInvalidException {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", REQUEST_ID);
    fieldSet.putSingle("URI", VALID_URI);
    fieldSet.putSingle("ReturnType", type.name());
    if (type == ReturnType.DISK) {
      fieldSet.putSingle("Filename", diskFile.getPath());
    }
    return new ClientGetMessage(fieldSet);
  }
}

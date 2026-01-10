package network.crypta.clients.fcp;

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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.FetchContext;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetReturnPlannerTest {
  private static final String VALID_URI =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String PAYLOAD_BIN = "payload.bin";
  private static final String REQUEST_ID = "id";

  @Mock private FetchContext fetchContext;
  @Mock private NodeClientCore core;
  @Mock private FCPConnectionHandler handler;
  @Mock private DdaAccessController ddaAccessController;

  @TempDir Path tempDir;

  @Test
  void constructor_whenIdentifierNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> new ClientGetReturnPlanner(null, false, fetchContext));
  }

  @Test
  void constructor_whenFetchContextNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> new ClientGetReturnPlanner(REQUEST_ID, false, null));
  }

  @Test
  void forGlobalRequest_whenReturnTypeNotDisk_returnsEmptySetup() throws Exception {
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);

    ClientGetReturnPlanner.ReturnSetup setup =
        planner.forGlobalRequest(ReturnType.DIRECT, null, false, core);

    assertAll(
        () -> assertNull(setup.bucket()),
        () -> assertNull(setup.targetFile()),
        () -> assertNull(setup.extension()));
    verifyNoInteractions(core);
  }

  @Test
  void forGlobalRequest_whenDiskNotAllowed_throwsNotAllowedException() {
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    File target = tempDir.resolve(PAYLOAD_BIN).toFile();
    when(core.allowDownloadTo(target)).thenReturn(false);

    assertThrows(
        NotAllowedException.class,
        () -> planner.forGlobalRequest(ReturnType.DISK, target, false, core));

    verify(core).allowDownloadTo(target);
  }

  @Test
  void forGlobalRequest_whenDiskAndZeroLengthFile_deletesAndReturnsSetup() throws Exception {
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    File target = tempDir.resolve(PAYLOAD_BIN).toFile();
    assertTrue(target.createNewFile());
    when(core.allowDownloadTo(target)).thenReturn(true);

    ClientGetReturnPlanner.ReturnSetup setup =
        planner.forGlobalRequest(ReturnType.DISK, target, true, core);

    assertAll(
        () -> assertInstanceOf(FileBucket.class, setup.bucket()),
        () -> assertEquals(target, setup.targetFile()),
        () -> assertEquals("bin", setup.extension()),
        () -> assertFalse(target.exists()));
  }

  @Test
  void forGlobalRequest_whenDiskAndExistingNonZeroFile_throwsIOException() throws Exception {
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    Files.writeString(targetPath, "data");
    File target = targetPath.toFile();
    when(core.allowDownloadTo(target)).thenReturn(true);

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> planner.forGlobalRequest(ReturnType.DISK, target, false, core));

    assertTrue(thrown.getMessage().contains("Target filename exists already"));
    assertTrue(target.exists());
  }

  @Test
  void forMessage_whenReturnTypeNotDisk_returnsEmptySetup() throws Exception {
    ClientGetMessage message = buildMessage(ReturnType.NONE, null);
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);

    ClientGetReturnPlanner.ReturnSetup setup = planner.forMessage(message, core, handler);

    assertAll(
        () -> assertNull(setup.bucket()),
        () -> assertNull(setup.targetFile()),
        () -> assertNull(setup.extension()));
    verifyNoInteractions(core, handler);
  }

  @Test
  void forMessage_whenDownloadNotAllowed_throwsMessageInvalidException() throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, true, fetchContext);
    when(core.allowDownloadTo(targetPath.toFile())).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class, () -> planner.forMessage(message, core, handler));

    assertAll(
        () -> assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode),
        () -> assertEquals(REQUEST_ID, thrown.ident),
        () -> assertTrue(thrown.global));
  }

  @Test
  void forMessage_whenDdaDenied_throwsMessageInvalidException() throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    when(core.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class, () -> planner.forMessage(message, core, handler));

    assertEquals(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, thrown.protocolCode);
  }

  @Test
  void forMessage_whenExistingNonZeroFile_throwsMessageInvalidExceptionWithCause()
      throws Exception {
    Path targetPath = tempDir.resolve(PAYLOAD_BIN);
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    Files.writeString(targetPath, "data");
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    when(core.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(true);

    MessageInvalidException thrown =
        assertThrows(
            MessageInvalidException.class, () -> planner.forMessage(message, core, handler));

    assertAll(
        () -> assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, thrown.protocolCode),
        () -> assertNotNull(thrown.getCause()),
        () -> assertInstanceOf(IOException.class, thrown.getCause()));
  }

  @Test
  void forMessage_whenAllowedAndFilterDataTrue_returnsSetupWithExtension() throws Exception {
    Path targetPath = tempDir.resolve("payload.txt");
    ClientGetMessage message = buildMessage(ReturnType.DISK, targetPath.toFile());
    ClientGetReturnPlanner planner = new ClientGetReturnPlanner(REQUEST_ID, false, fetchContext);
    when(core.allowDownloadTo(targetPath.toFile())).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaAccessController);
    when(ddaAccessController.allowDDAFrom(targetPath.toFile(), true)).thenReturn(true);
    when(fetchContext.getFilterData()).thenReturn(true);

    ClientGetReturnPlanner.ReturnSetup setup = planner.forMessage(message, core, handler);

    assertAll(
        () -> assertInstanceOf(FileBucket.class, setup.bucket()),
        () -> assertEquals(targetPath.toFile(), setup.targetFile()),
        () -> assertEquals("txt", setup.extension()));
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

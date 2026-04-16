package network.crypta.clients.fcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentPutDirTest {

  private static final String DISK_FILE_NAME = "disk.dat";
  private static final String REDIRECT_FILE_NAME = "redirect.bin";
  private static final String UPLOAD_FROM_KEY = "UploadFrom";
  private static final String DATA_LENGTH_KEY = "DataLength";
  private static final String CONTENT_TYPE_KEY = "Metadata.ContentType";
  private static final String PRIVATE_URI_KEY = "PrivateURI";
  private static final String CLIENT_TOKEN_KEY = "ClientToken";
  private static final String CODECS_KEY = "Codecs";
  private static final String SPLITFILE_KEY = "SplitfileCryptoKey";
  private static final String FILENAME_KEY = "Filename";
  private static final String FILE_TXT_NAME = "file.txt";
  private static final String DEFAULT_NAME = "default";
  private static final String[] ROOT_KEYS =
      new String[] {
        "Identifier",
        "URI",
        PRIVATE_URI_KEY,
        "Verbosity",
        "Persistence",
        "PriorityClass",
        "Global",
        "PutDirType",
        "CompatibilityMode",
        "DefaultName",
        CLIENT_TOKEN_KEY,
        "Started",
        "MaxRetries",
        "DontCompress",
        CODECS_KEY,
        "RealTime",
        SPLITFILE_KEY
      };

  @Mock FCPConnectionHandler connectionHandler;

  @Test
  void getFieldSet_whenDiskDirectAndRedirectEntries_populatesAllFields() {
    FreenetURI publicUri = new FreenetURI("CHK", "public");
    FreenetURI privateUri = new FreenetURI("SSK", "private");
    FreenetURI redirectUri = new FreenetURI("CHK", "target");

    List<PersistentPutDirEntrySnapshot> manifestEntries =
        List.of(
            new PersistentPutDirEntrySnapshot(
                DISK_FILE_NAME,
                ClientPutBase.UploadFrom.DISK,
                4,
                "disk/path/" + DISK_FILE_NAME,
                "text/plain",
                null),
            new PersistentPutDirEntrySnapshot(
                "subdir/nested.bin",
                ClientPutBase.UploadFrom.DIRECT,
                8,
                null,
                "application/octet-stream",
                null),
            new PersistentPutDirEntrySnapshot(
                REDIRECT_FILE_NAME,
                ClientPutBase.UploadFrom.REDIRECT,
                -1,
                null,
                null,
                redirectUri));

    byte[] cryptoKey = new byte[] {0x0a, 0x0b, 0x0c};
    SimpleFieldSet fs = buildFullFieldSet(manifestEntries, publicUri, privateUri, cryptoKey);

    Map<String, String> expectedRoot = new LinkedHashMap<>();
    expectedRoot.put("Identifier", "id-123");
    expectedRoot.put("URI", publicUri.toString(false, false));
    expectedRoot.put(PRIVATE_URI_KEY, privateUri.toString(false, false));
    expectedRoot.put("Verbosity", "2");
    expectedRoot.put("Persistence", "forever");
    expectedRoot.put("PriorityClass", "3");
    expectedRoot.put("Global", "true");
    expectedRoot.put("PutDirType", "disk");
    expectedRoot.put("CompatibilityMode", "COMPAT_1468");
    expectedRoot.put("DefaultName", "index.html");
    expectedRoot.put(CLIENT_TOKEN_KEY, "client-token");
    expectedRoot.put("Started", "true");
    expectedRoot.put("MaxRetries", "5");
    expectedRoot.put("DontCompress", "true");
    expectedRoot.put(CODECS_KEY, "gzip");
    expectedRoot.put("RealTime", "true");
    expectedRoot.put(SPLITFILE_KEY, "0a0b0c");
    assertEquals(expectedRoot, extract(fs, ROOT_KEYS));

    SimpleFieldSet files = fs.subset("Files");
    assertNotNull(files);
    assertEquals("3", files.get("Count"));

    SimpleFieldSet first = files.subset("0");
    assertNotNull(first);
    Map<String, String> expectedFirst = new LinkedHashMap<>();
    expectedFirst.put("Name", DISK_FILE_NAME);
    expectedFirst.put(UPLOAD_FROM_KEY, "disk");
    expectedFirst.put(FILENAME_KEY, "disk/path/" + DISK_FILE_NAME);
    expectedFirst.put(DATA_LENGTH_KEY, "4");
    expectedFirst.put(CONTENT_TYPE_KEY, "text/plain");
    assertEquals(
        expectedFirst,
        extract(first, "Name", UPLOAD_FROM_KEY, FILENAME_KEY, DATA_LENGTH_KEY, CONTENT_TYPE_KEY));

    SimpleFieldSet second = files.subset("1");
    assertNotNull(second);
    Map<String, String> expectedSecond = new LinkedHashMap<>();
    expectedSecond.put("Name", "subdir/nested.bin");
    expectedSecond.put(UPLOAD_FROM_KEY, "direct");
    expectedSecond.put(DATA_LENGTH_KEY, "8");
    expectedSecond.put(CONTENT_TYPE_KEY, "application/octet-stream");
    assertEquals(
        expectedSecond,
        extract(second, "Name", UPLOAD_FROM_KEY, DATA_LENGTH_KEY, CONTENT_TYPE_KEY));

    SimpleFieldSet third = files.subset("2");
    assertNotNull(third);
    Map<String, String> expectedThird = new LinkedHashMap<>();
    expectedThird.put("Name", REDIRECT_FILE_NAME);
    expectedThird.put(UPLOAD_FROM_KEY, "redirect");
    expectedThird.put("TargetURI", redirectUri.toString());
    expectedThird.put(DATA_LENGTH_KEY, null);
    expectedThird.put(CONTENT_TYPE_KEY, null);
    assertEquals(
        expectedThird,
        extract(third, "Name", UPLOAD_FROM_KEY, "TargetURI", DATA_LENGTH_KEY, CONTENT_TYPE_KEY));
  }

  @Test
  void getFieldSet_whenOptionalFieldsOmitted_doesNotIncludeThem() {
    SimpleFieldSet fs =
        buildOptionalFieldSet(
            List.of(
                new PersistentPutDirEntrySnapshot(
                    FILE_TXT_NAME, ClientPutBase.UploadFrom.DIRECT, 1, null, null, null)));

    assertNull(fs.get(PRIVATE_URI_KEY));
    assertNull(fs.get(CLIENT_TOKEN_KEY));
    assertNull(fs.get(CODECS_KEY));
    assertNull(fs.get(SPLITFILE_KEY));
  }

  @Test
  void getFieldSet_whenUploadSourceUnknown_omitsUploadFromButKeepsOtherFields() {
    PersistentPutDir message =
        buildMessage(
            "id-wrap",
            Persistence.REBOOT,
            false,
            List.of(
                new PersistentPutDirEntrySnapshot(
                    "wrapped.dat", null, 12, null, "application/octet-stream", null)));

    SimpleFieldSet filesSubset = message.getFieldSet().subset("Files");
    assertNotNull(filesSubset);
    SimpleFieldSet fileSubset = filesSubset.subset("0");
    assertNotNull(fileSubset);
    assertNull(fileSubset.get(UPLOAD_FROM_KEY));
    assertEquals("12", fileSubset.get(DATA_LENGTH_KEY));
    assertEquals("application/octet-stream", fileSubset.get(CONTENT_TYPE_KEY));
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithContext() {
    PersistentPutDir message =
        buildMessage(
            "ident",
            Persistence.CONNECTION,
            true,
            List.of(
                new PersistentPutDirEntrySnapshot(
                    FILE_TXT_NAME, ClientPutBase.UploadFrom.DIRECT, 1, null, null, null)));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(connectionHandler));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals("ident", ex.ident);
    assertTrue(ex.global);
  }

  private Map<String, String> extract(SimpleFieldSet fieldSet, String... keys) {
    Map<String, String> values = new LinkedHashMap<>();
    for (String key : keys) {
      values.put(key, fieldSet.get(key));
    }
    return values;
  }

  private SimpleFieldSet buildFullFieldSet(
      List<PersistentPutDirEntrySnapshot> manifestEntries,
      FreenetURI publicUri,
      FreenetURI privateUri,
      byte[] cryptoKey) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            publicUri, "id-123", 2, (short) 3, Persistence.FOREVER, true, "client-token", true);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            privateUri, true, 5, FcpCompatibilityMode.COMPAT_1468, true, "gzip", cryptoKey);
    PersistentPutDir message =
        new PersistentPutDir(requestParams, metadata, "index.html", manifestEntries, true);
    return message.getFieldSet();
  }

  private SimpleFieldSet buildOptionalFieldSet(
      List<PersistentPutDirEntrySnapshot> manifestEntries) {
    return buildMessage("id-opt", Persistence.CONNECTION, false, manifestEntries).getFieldSet();
  }

  private PersistentPutDir buildMessage(
      String identifier,
      Persistence persistence,
      boolean global,
      List<PersistentPutDirEntrySnapshot> manifestEntries) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI("CHK", "pub"),
            identifier,
            0,
            (short) 1,
            persistence,
            false,
            null,
            global);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            null, false, 0, FcpCompatibilityMode.COMPAT_CURRENT, false, null, null);
    return new PersistentPutDir(requestParams, metadata, DEFAULT_NAME, manifestEntries, false);
  }
}

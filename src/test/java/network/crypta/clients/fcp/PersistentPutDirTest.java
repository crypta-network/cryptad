package network.crypta.clients.fcp;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.DelayedFreeRandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PersistentFileTracker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
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
  private static final String WRAPPED_FILE_NAME = "wrapped.dat";
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

  @TempDir Path tempDir;

  @Mock FCPConnectionHandler connectionHandler;

  @Mock Node node;

  @Test
  void getFieldSet_whenDiskDirectAndRedirectElements_populatesAllFields() throws Exception {
    FreenetURI publicUri = new FreenetURI("CHK", "public");
    FreenetURI privateUri = new FreenetURI("SSK", "private");

    File diskFile = Files.createFile(tempDir.resolve(DISK_FILE_NAME)).toFile();
    FileBucket diskBucket = new FileBucket(diskFile, false, false, false, false);
    ManifestElement diskElement = new ManifestElement(DISK_FILE_NAME, diskBucket, "text/plain", 4);

    NullBucket directBucket = new NullBucket(8);
    ManifestElement nestedElement =
        new ManifestElement("nested.bin", directBucket, "application/octet-stream", 8);

    FreenetURI redirectUri = new FreenetURI("CHK", "target");
    ManifestElement redirectElement = new ManifestElement(REDIRECT_FILE_NAME, redirectUri, null);

    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(DISK_FILE_NAME, diskElement);
    Map<String, Object> subdir = new LinkedHashMap<>();
    subdir.put("nested.bin", nestedElement);
    manifest.put("subdir", subdir);
    manifest.put(REDIRECT_FILE_NAME, redirectElement);

    byte[] cryptoKey = new byte[] {0x0a, 0x0b, 0x0c};
    SimpleFieldSet fs = buildFullFieldSet(manifest, publicUri, privateUri, cryptoKey);

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
    expectedFirst.put(FILENAME_KEY, diskFile.getPath());
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
    NullBucket bucket = new NullBucket(1);
    ManifestElement element = new ManifestElement(FILE_TXT_NAME, bucket, null, 1);
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(FILE_TXT_NAME, element);

    SimpleFieldSet fs = buildOptionalFieldSet(manifest);

    assertNull(fs.get(PRIVATE_URI_KEY));
    assertNull(fs.get(CLIENT_TOKEN_KEY));
    assertNull(fs.get(CODECS_KEY));
    assertNull(fs.get(SPLITFILE_KEY));
  }

  @Test
  void generateFieldSet_whenBucketWrappedInDelayedFree_usesUnderlyingBucket() {
    File underlyingFile = tempDir.resolve(WRAPPED_FILE_NAME).toFile();
    RandomAccessBucket underlyingBucket =
        new FileBucket(underlyingFile, false, false, false, false);
    PersistentFileTracker tracker = Mockito.mock(PersistentFileTracker.class);
    Mockito.when(tracker.commitID()).thenReturn(1L);

    DelayedFreeRandomAccessBucket wrapped =
        new DelayedFreeRandomAccessBucket(tracker, underlyingBucket);
    ManifestElement element = new ManifestElement(WRAPPED_FILE_NAME, wrapped, null, 12);
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(WRAPPED_FILE_NAME, element);

    PersistentPutDir message = buildWrappedMessage(manifest);
    SimpleFieldSet fileSubset = message.getFieldSet().subset("Files").subset("0");
    assertEquals("disk", fileSubset.get(UPLOAD_FROM_KEY));
    assertEquals(underlyingFile.getPath(), fileSubset.get(FILENAME_KEY));
  }

  private Map<String, String> extract(SimpleFieldSet fieldSet, String... keys) {
    Map<String, String> values = new LinkedHashMap<>();
    for (String key : keys) {
      values.put(key, fieldSet.get(key));
    }
    return values;
  }

  private SimpleFieldSet buildFullFieldSet(
      Map<String, Object> manifest, FreenetURI publicUri, FreenetURI privateUri, byte[] cryptoKey) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            publicUri, "id-123", 2, (short) 3, Persistence.FOREVER, true, "client-token", true);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            privateUri,
            true,
            5,
            InsertContext.CompatibilityMode.COMPAT_1468,
            true,
            "gzip",
            cryptoKey);
    PersistentPutDir message =
        new PersistentPutDir(
            requestParams, metadata, "index.html", new LinkedHashMap<>(manifest), true);
    return message.getFieldSet();
  }

  private SimpleFieldSet buildOptionalFieldSet(Map<String, Object> manifest) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI("CHK", "pub"),
            "id-opt",
            0,
            (short) 1,
            Persistence.CONNECTION,
            false,
            null,
            false);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            null, false, 0, InsertContext.CompatibilityMode.COMPAT_CURRENT, false, null, null);
    PersistentPutDir message =
        new PersistentPutDir(
            requestParams, metadata, DEFAULT_NAME, new LinkedHashMap<>(manifest), false);
    return message.getFieldSet();
  }

  private PersistentPutDir buildWrappedMessage(Map<String, Object> manifest) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI("CHK", "pub2"),
            "id-wrap",
            1,
            (short) 1,
            Persistence.REBOOT,
            false,
            null,
            false);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            null, false, 1, InsertContext.CompatibilityMode.COMPAT_1250, false, null, null);
    return new PersistentPutDir(
        requestParams, metadata, "wrapped", new LinkedHashMap<>(manifest), false);
  }

  private PersistentPutDir buildRunMessage(Map<String, Object> manifest) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI("CHK", "pub3"),
            "ident",
            1,
            (short) 1,
            Persistence.CONNECTION,
            false,
            null,
            true);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            null, false, 0, InsertContext.CompatibilityMode.COMPAT_CURRENT, false, null, null);
    return new PersistentPutDir(
        requestParams, metadata, DEFAULT_NAME, new LinkedHashMap<>(manifest), false);
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithContext() {
    NullBucket bucket = new NullBucket();
    ManifestElement element = new ManifestElement(FILE_TXT_NAME, bucket, null, 1);
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(FILE_TXT_NAME, element);

    PersistentPutDir message = buildRunMessage(manifest);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(connectionHandler));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals("ident", ex.ident);
    assertTrue(ex.global);
  }

  @Test
  void constructor_whenBucketTypeUnknown_throwsIllegalStateException() {
    RandomAccessBucket unknownBucket = Mockito.mock(RandomAccessBucket.class);
    ManifestElement element = new ManifestElement("unknown.bin", unknownBucket, null, 2);
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put("unknown.bin", element);

    assertThrows(IllegalStateException.class, () -> createPersistentPutDirWith(manifest));
  }

  private void createPersistentPutDirWith(Map<String, Object> manifest) {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            new FreenetURI("CHK", "pub4"),
            "id-bad",
            0,
            (short) 1,
            Persistence.CONNECTION,
            false,
            null,
            false);
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            null, false, 0, InsertContext.CompatibilityMode.COMPAT_CURRENT, false, null, null);
    new PersistentPutDir(
        requestParams, metadata, DEFAULT_NAME, new LinkedHashMap<>(manifest), false);
  }
}

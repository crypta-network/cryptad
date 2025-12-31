package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.config.SubConfig;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.support.api.StringArrCallback;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeClientCoreTransferPolicyTest {
  private static final String DOWNLOADS_TOKEN = "downloads";
  private static final String UPLOADS_DIR_NAME = "uploads";
  private static final String OUTSIDE_FILE_NAME = "outside.bin";
  private static final String DOWNLOAD_ALLOWED_DIRS_KEY = "downloadAllowedDirs";
  private static final String UPLOAD_ALLOWED_DIRS_KEY = "uploadAllowedDirs";
  private static final String DOWNLOAD_ALLOWED_DIRS_SHORT = "NodeClientCore.downloadAllowedDirs";
  private static final String DOWNLOAD_ALLOWED_DIRS_LONG = "NodeClientCore.downloadAllowedDirsLong";
  private static final String UPLOAD_ALLOWED_DIRS_SHORT = "NodeClientCore.uploadAllowedDirs";
  private static final String UPLOAD_ALLOWED_DIRS_LONG = "NodeClientCore.uploadAllowedDirsLong";

  @TempDir Path tempDir;

  @Mock Node node;
  @Mock SecurityLevels securityLevels;
  @Mock SubConfig nodeConfig;

  private File downloadsDir;
  private NodeClientCoreTransferPolicy policy;

  @BeforeEach
  void setUp() throws IOException {
    downloadsDir = tempDir.resolve(DOWNLOADS_TOKEN).toFile();
    Files.createDirectories(downloadsDir.toPath());
    policy = new NodeClientCoreTransferPolicy(node, downloadsDir);
  }

  @ParameterizedTest
  @MethodSource("downloadThreatLevels")
  void allowDownloadTo_whenAllowedEverywhere_respectsPhysicalThreatLevel(
      PHYSICAL_THREAT_LEVEL level, boolean expected) {
    stubPhysicalThreatLevel(level);
    policy.setDownloadAllowedDirs(new String[] {"all"});

    File target = tempDir.resolve("target.bin").toFile();

    assertEquals(expected, policy.allowDownloadTo(target));
  }

  private static Stream<Arguments> downloadThreatLevels() {
    return Stream.of(
        Arguments.of(PHYSICAL_THREAT_LEVEL.LOW, true),
        Arguments.of(PHYSICAL_THREAT_LEVEL.NORMAL, true),
        Arguments.of(PHYSICAL_THREAT_LEVEL.HIGH, true),
        Arguments.of(PHYSICAL_THREAT_LEVEL.MAXIMUM, false));
  }

  @Test
  void setDownloadAllowedDirs_whenEmpty_setsDownloadDisabled() {
    policy.setDownloadAllowedDirs(new String[] {});

    assertTrue(policy.isDownloadDisabled());
  }

  @Test
  void allowDownloadTo_whenNoAllowedDirs_deniesTarget() {
    stubPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
    policy.setDownloadAllowedDirs(new String[] {});

    File target = tempDir.resolve("target.bin").toFile();

    assertFalse(policy.allowDownloadTo(target));
  }

  @Test
  void allowDownloadTo_whenDownloadsDirIncluded_allowsChild() {
    stubPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
    policy.setDownloadAllowedDirs(new String[] {DOWNLOADS_TOKEN});

    File target = downloadsDir.toPath().resolve("child.bin").toFile();

    assertTrue(policy.allowDownloadTo(target));
  }

  @Test
  void allowDownloadTo_whenDownloadsDirIncluded_deniesOutside() {
    stubPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
    policy.setDownloadAllowedDirs(new String[] {DOWNLOADS_TOKEN});

    File target = tempDir.resolve(OUTSIDE_FILE_NAME).toFile();

    assertFalse(policy.allowDownloadTo(target));
  }

  @Test
  void getAllowedDownloadDirs_whenCalled_returnsInternalArrayReference() {
    File allowedDir = tempDir.resolve("allowed").toFile();
    policy.setDownloadAllowedDirs(new String[] {allowedDir.getPath()});

    File[] first = policy.getAllowedDownloadDirs();
    File[] second = policy.getAllowedDownloadDirs();

    assertSame(first, second);
  }

  @Test
  void setDownloadAllowedDirs_whenArrayContainsNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> policy.setDownloadAllowedDirs(new String[] {null}));
  }

  @Test
  void allowUploadFrom_whenAllowedEverywhere_returnsTrue() {
    policy.setUploadAllowedDirs(new String[] {"all"});

    File target = tempDir.resolve("upload.bin").toFile();

    assertTrue(policy.allowUploadFrom(target));
  }

  @Test
  void allowUploadFrom_whenRestricted_allowsChild() {
    File allowedDir = tempDir.resolve(UPLOADS_DIR_NAME).toFile();
    policy.setUploadAllowedDirs(new String[] {allowedDir.getPath()});

    File target = allowedDir.toPath().resolve("child.bin").toFile();

    assertTrue(policy.allowUploadFrom(target));
  }

  @Test
  void allowUploadFrom_whenRestricted_deniesOutside() {
    File allowedDir = tempDir.resolve(UPLOADS_DIR_NAME).toFile();
    policy.setUploadAllowedDirs(new String[] {allowedDir.getPath()});

    File target = tempDir.resolve(OUTSIDE_FILE_NAME).toFile();

    assertFalse(policy.allowUploadFrom(target));
  }

  @Test
  void registerDownloadAllowedDirs_whenCalled_registersCallbackAndReturnsNextSortOrder() {
    when(nodeConfig.getStringArr(DOWNLOAD_ALLOWED_DIRS_KEY)).thenReturn(new String[] {"all"});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    int nextSortOrder = policy.registerDownloadAllowedDirs(init, 4);

    verify(nodeConfig)
        .register(
            eq(DOWNLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(4),
            eq(true),
            eq(true),
            eq(DOWNLOAD_ALLOWED_DIRS_SHORT),
            eq(DOWNLOAD_ALLOWED_DIRS_LONG),
            any(StringArrCallback.class));
    assertEquals(5, nextSortOrder);
  }

  @Test
  void registerDownloadAllowedDirs_whenCallbackGet_returnsNormalizedValues() {
    File allowedDir = tempDir.resolve("allowed").toFile();
    when(nodeConfig.getStringArr(DOWNLOAD_ALLOWED_DIRS_KEY))
        .thenReturn(new String[] {DOWNLOADS_TOKEN, allowedDir.getPath()});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    policy.registerDownloadAllowedDirs(init, 0);

    ArgumentCaptor<StringArrCallback> callbackCaptor =
        ArgumentCaptor.forClass(StringArrCallback.class);
    verify(nodeConfig)
        .register(
            eq(DOWNLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(0),
            eq(true),
            eq(true),
            eq(DOWNLOAD_ALLOWED_DIRS_SHORT),
            eq(DOWNLOAD_ALLOWED_DIRS_LONG),
            callbackCaptor.capture());

    assertArrayEquals(
        new String[] {allowedDir.getPath(), DOWNLOADS_TOKEN}, callbackCaptor.getValue().get());
  }

  @Test
  void registerDownloadAllowedDirs_whenCallbackSet_updatesPolicy() {
    stubPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
    when(nodeConfig.getStringArr(DOWNLOAD_ALLOWED_DIRS_KEY))
        .thenReturn(new String[] {DOWNLOADS_TOKEN});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    policy.registerDownloadAllowedDirs(init, 0);

    ArgumentCaptor<StringArrCallback> callbackCaptor =
        ArgumentCaptor.forClass(StringArrCallback.class);
    verify(nodeConfig)
        .register(
            eq(DOWNLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(0),
            eq(true),
            eq(true),
            eq(DOWNLOAD_ALLOWED_DIRS_SHORT),
            eq(DOWNLOAD_ALLOWED_DIRS_LONG),
            callbackCaptor.capture());

    assertDoesNotThrow(() -> callbackCaptor.getValue().set(new String[] {"all"}));

    File target = tempDir.resolve(OUTSIDE_FILE_NAME).toFile();

    assertTrue(policy.allowDownloadTo(target));
  }

  @Test
  void registerUploadAllowedDirs_whenCalled_registersCallbackAndReturnsNextSortOrder() {
    when(nodeConfig.getStringArr(UPLOAD_ALLOWED_DIRS_KEY)).thenReturn(new String[] {"all"});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    int nextSortOrder = policy.registerUploadAllowedDirs(init, 3);

    verify(nodeConfig)
        .register(
            eq(UPLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(3),
            eq(true),
            eq(true),
            eq(UPLOAD_ALLOWED_DIRS_SHORT),
            eq(UPLOAD_ALLOWED_DIRS_LONG),
            any(StringArrCallback.class));
    assertEquals(4, nextSortOrder);
  }

  @Test
  void registerUploadAllowedDirs_whenCallbackGet_returnsConfiguredValues() {
    File allowedDir = tempDir.resolve(UPLOADS_DIR_NAME).toFile();
    when(nodeConfig.getStringArr(UPLOAD_ALLOWED_DIRS_KEY))
        .thenReturn(new String[] {allowedDir.getPath()});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    policy.registerUploadAllowedDirs(init, 0);

    ArgumentCaptor<StringArrCallback> callbackCaptor =
        ArgumentCaptor.forClass(StringArrCallback.class);
    verify(nodeConfig)
        .register(
            eq(UPLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(0),
            eq(true),
            eq(true),
            eq(UPLOAD_ALLOWED_DIRS_SHORT),
            eq(UPLOAD_ALLOWED_DIRS_LONG),
            callbackCaptor.capture());

    assertArrayEquals(new String[] {allowedDir.getPath()}, callbackCaptor.getValue().get());
  }

  @Test
  void registerUploadAllowedDirs_whenCallbackSet_updatesPolicy() {
    when(nodeConfig.getStringArr(UPLOAD_ALLOWED_DIRS_KEY)).thenReturn(new String[] {});
    NodeClientCoreInit init = new NodeClientCoreInit(null, nodeConfig, null, null);

    policy.registerUploadAllowedDirs(init, 0);

    ArgumentCaptor<StringArrCallback> callbackCaptor =
        ArgumentCaptor.forClass(StringArrCallback.class);
    verify(nodeConfig)
        .register(
            eq(UPLOAD_ALLOWED_DIRS_KEY),
            any(String[].class),
            eq(0),
            eq(true),
            eq(true),
            eq(UPLOAD_ALLOWED_DIRS_SHORT),
            eq(UPLOAD_ALLOWED_DIRS_LONG),
            callbackCaptor.capture());

    assertDoesNotThrow(() -> callbackCaptor.getValue().set(new String[] {"all"}));

    File target = tempDir.resolve(OUTSIDE_FILE_NAME).toFile();

    assertTrue(policy.allowUploadFrom(target));
  }

  private void stubPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL level) {
    when(node.getSecurityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(level);
  }
}

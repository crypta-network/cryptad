package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.NodeSSK;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class NodeClientCoreTest {

  @Mock private Node node;
  @Mock private SecurityLevels securityLevels;
  @Mock private SimpleToadletServer toadlets;
  @Mock private RequestStarterGroup requestStarters;
  @Mock private ClientRequestScheduler schedulerBulk;
  @Mock private ClientRequestScheduler schedulerRt;
  @Mock private RandomSource rng;

  @TempDir Path tempDir; // base dir for downloads and test files

  private NodeClientCore core;

  @BeforeEach
  void setUp() throws Exception {
    // Create a mock that calls real methods without running the heavy constructor
    core =
        Mockito.mock(
            NodeClientCore.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));

    // Inject required collaborators/fields via reflection to avoid full Node/Config bootstrapping
    setField(core, "random", rng);
    setField(core, "node", node);
    when(node.getSecurityLevels()).thenReturn(securityLevels);

    setField(core, "downloadsDir", tempDir.toFile());

    ClientEndpoints endpoints = new ClientEndpoints(Mockito.mock(FCPServer.class), null, toadlets);
    setField(core, "endpoints", endpoints);
    setField(core, "requestStarters", requestStarters);

    // sensible default unless a test overrides
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
  }

  @Test
  void makeUID_whenRandomReturnsMinusOneFirst_expectSkipsAndReturnsNonMinusOne() {
    when(rng.nextLong()).thenReturn(-1L, 1234L);
    long uid = core.makeUID();
    assertNotEquals(-1L, uid);
    assertEquals(1234L, uid);
  }

  @Test
  void isDownloadDisabled_whenNoAllowedDirs_expectTrue() {
    core.setDownloadAllowedDirs(new String[] {});
    assertTrue(core.isDownloadDisabled());

    // Also verify that with no allowed dirs, a path is rejected
    File f = tempDir.resolve("file.bin").toFile();
    assertFalse(core.allowDownloadTo(f));
  }

  @Test
  void allowDownloadTo_whenPhysicalLevelMaximum_expectFalseRegardlessOfDirs() {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.MAXIMUM);
    core.setDownloadAllowedDirs(new String[] {"all"});
    File f = tempDir.resolve("any.bin").toFile();
    assertFalse(core.allowDownloadTo(f));
  }

  @Test
  void allowDownloadTo_whenDownloadsDirIncluded_expectTrueInsideDownloadsFalseOutside()
      throws Exception {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
    core.setDownloadAllowedDirs(new String[] {"downloads"});

    Path inside = tempDir.resolve("sub/inside.dat");
    Files.createDirectories(inside.getParent());
    Path outsideDir = Files.createTempDirectory("outside-");
    File outside = outsideDir.resolve("out.dat").toFile();

    assertTrue(core.allowDownloadTo(inside.toFile()));
    assertFalse(core.allowDownloadTo(outside));
  }

  @Test
  void allowDownloadTo_whenExplicitDirAllowed_expectTrueForSubpathsOnly() throws Exception {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
    Path allowed = tempDir.resolve("allowed");
    Files.createDirectories(allowed);
    core.setDownloadAllowedDirs(new String[] {allowed.toFile().getAbsolutePath()});

    File inSub = allowed.resolve("deep/nested/file.dat").toFile();
    Path other = Files.createTempDirectory("other-");
    File notAllowed = other.resolve("na.bin").toFile();

    assertTrue(core.allowDownloadTo(inSub));
    assertFalse(core.allowDownloadTo(notAllowed));
  }

  @Test
  void setDownloadAllowedDirs_whenAllAndExplicitDirs_expectInternalStateReflectedByGetters() {
    Path a = tempDir.resolve("A");
    Path b = tempDir.resolve("B");
    core.setDownloadAllowedDirs(
        new String[] {a.toFile().getAbsolutePath(), b.toFile().getAbsolutePath()});
    File[] dirs = core.getAllowedDownloadDirs();
    // Order is preserved for concrete paths; "downloads" and "all" are not part of this array
    assertArrayEquals(new File[] {a.toFile(), b.toFile()}, dirs);
  }

  @Test
  void allowUploadFrom_whenAllEnabled_expectTrueForAnyPath() {
    core.setUploadAllowedDirs(new String[] {"all"});
    File anywhere = tempDir.getParent().resolve("anywhere.txt").toFile();
    assertTrue(core.allowUploadFrom(anywhere));
  }

  @Test
  void allowUploadFrom_whenSpecificDirEnabled_expectOnlyThatDirAccepted() throws Exception {
    Path up = tempDir.resolve("uploads");
    Files.createDirectories(up);
    core.setUploadAllowedDirs(new String[] {up.toFile().getAbsolutePath()});

    File inside = up.resolve("ok.bin").toFile();
    Path other = Files.createTempDirectory("not-up-");
    File outside = other.resolve("nope.bin").toFile();

    assertTrue(core.allowUploadFrom(inside));
    assertFalse(core.allowUploadFrom(outside));
  }

  @Test
  void queueOfferedKey_whenSSKAndRealTime_expectDelegatedToAppropriateScheduler() {
    NodeSSK key =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE], new byte[NodeSSK.E_H_DOCNAME_SIZE], (byte) 1);

    when(requestStarters.getScheduler(true, false, true)).thenReturn(schedulerRt);

    core.queueOfferedKey(key, true);

    verify(schedulerRt, times(1)).queueOfferedKey(key, true);
  }

  @Test
  void dequeueOfferedKey_whenSSK_expectBothBulkAndRealtimeSchedulersNotified() {
    NodeSSK key =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE], new byte[NodeSSK.E_H_DOCNAME_SIZE], (byte) 1);

    when(requestStarters.getScheduler(true, false, false)).thenReturn(schedulerBulk);
    when(requestStarters.getScheduler(true, false, true)).thenReturn(schedulerRt);

    core.dequeueOfferedKey(key);

    verify(schedulerBulk, times(1)).dequeueOfferedKey(key);
    verify(schedulerRt, times(1)).dequeueOfferedKey(key);
  }

  @Test
  void linkFilterProvider_and_fproxyFlags_and_bookmarks_areDelegatedToToadletContainer() {
    BookmarkManager bm = Mockito.mock(BookmarkManager.class);
    when(toadlets.getBookmarks()).thenReturn(bm);
    when(toadlets.getBookmarkURIs()).thenReturn(new network.crypta.keys.FreenetURI[0]);
    when(toadlets.isAdvancedModeEnabled()).thenReturn(true);
    when(toadlets.isFProxyJavascriptEnabled()).thenReturn(true);

    assertSame(toadlets, core.getEndpoints().getToadletContainer());
    assertSame(bm, core.getEndpoints().getToadletContainer().getBookmarks());
    assertEquals(0, core.getEndpoints().getToadletContainer().getBookmarkURIs().length);
    assertTrue(core.isAdvancedModeEnabled());
    assertTrue(core.isFProxyJavascriptEnabled());
  }

  @Test
  void fproxySetterGetter_and_myName_delegations_work() {
    FProxyToadlet fproxy = Mockito.mock(FProxyToadlet.class);
    core.getEndpoints().setFProxy(fproxy);
    assertSame(fproxy, core.getEndpoints().getFProxy());

    when(node.getMyName()).thenReturn("MyNode");
    assertEquals("MyNode", core.getMyName());
  }

  // --- helpers ---
  private static void setField(Object target, String name, Object value) throws Exception {
    Field f = NodeClientCore.class.getDeclaredField(name);
    f.setAccessible(true);
    f.set(target, value);
  }
}

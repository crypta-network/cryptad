package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.tools.ToolProvider;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetStateTest {

  @Test
  void constructor_whenRequestNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ClientGetState(null));
  }

  @Test
  void constructor_whenCreated_initializesDefaultState() {
    ClientGet request = new ClientGet();
    ClientGetState state = new ClientGetState(request);

    assertFalse(state.hasSucceeded());
    assertEquals(-1L, state.getFoundDataLength());
    assertNull(state.getFoundDataMimeType());
    assertNull(state.getProgressPending());
    assertFalse(state.hasSentToNetwork());
    assertNull(state.getExpectedHashes());
    assertNull(state.getFailedMessage());
    assertNotNull(state.getCompatibilityAnalyser());
    assertArrayEquals(
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_UNKNOWN, FcpCompatibilityMode.COMPAT_UNKNOWN
        },
        state.getCompatibilityMode());
    assertTrue(state.getDontCompress());
    assertNull(state.getOverriddenSplitfileCryptoKey());
    assertNull(state.getReturnBucketDirect());
  }

  @Test
  void scalarSetters_whenUpdated_reflectLatestValues() {
    ClientGetState state = new ClientGetState(new ClientGet());

    for (boolean expected : new boolean[] {true, false}) {
      state.setSucceeded(expected);
      assertEquals(expected, state.hasSucceeded());
    }
    state.setFoundDataLength(42L);
    state.setFoundDataMimeType("text/plain");

    assertEquals(42L, state.getFoundDataLength());
    assertEquals("text/plain", state.getFoundDataMimeType());
  }

  @Test
  void progressPending_whenSet_reflectsValue() {
    ClientGetState state = new ClientGetState(new ClientGet());
    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);

    state.setProgressPending(progress);
    assertSame(progress, state.getProgressPending());
  }

  @Test
  void markSentToNetwork_whenInvoked_setsFlagTrue() {
    ClientGetState state = new ClientGetState(new ClientGet());

    state.markSentToNetwork();

    assertTrue(state.hasSentToNetwork());
  }

  @Test
  void expectedHashes_whenInitiallyAbsent_trySetStoresAndReturnsTrue() {
    ClientGetState state = new ClientGetState(new ClientGet());
    ExpectedHashes hashes = new ExpectedHashes(new HashResult[0], "req", false);

    assertTrue(state.trySetExpectedHashes(hashes));
    assertSame(hashes, state.getExpectedHashes());
  }

  @Test
  void expectedHashes_whenAlreadyPresent_trySetReturnsFalseAndKeepsOriginal() {
    ClientGetState state = new ClientGetState(new ClientGet());
    ExpectedHashes original = new ExpectedHashes(new HashResult[0], "req-original", false);
    ExpectedHashes replacement = new ExpectedHashes(new HashResult[0], "req-replacement", false);
    state.setExpectedHashes(original);

    assertFalse(state.trySetExpectedHashes(replacement));
    assertSame(original, state.getExpectedHashes());
  }

  @Test
  void expectedHashes_whenCleared_becomesNull() {
    ClientGetState state = new ClientGetState(new ClientGet());
    state.setExpectedHashes(new ExpectedHashes(new HashResult[0], "req", false));

    state.clearExpectedHashes();

    assertNull(state.getExpectedHashes());
  }

  @Test
  void failedMessage_whenSetAndReplaced_reflectsLatestMessage() throws Exception {
    ClientGetState state = new ClientGetState(new ClientGet());
    FetchException failure =
        new FetchException(
            FetchExceptionMode.PERMANENT_REDIRECT, "redirect", new FreenetURI("KSK@redirect"));
    GetFailedMessage message = new GetFailedMessage(failure, "req", false);
    GetFailedMessage replacement = new GetFailedMessage(failure, "req-replacement", false);

    state.setFailedMessage(message);
    assertSame(message, state.getFailedMessage());

    state.setFailedMessage(replacement);
    assertSame(replacement, state.getFailedMessage());
  }

  @Test
  void setCompatibilityAnalyser_whenCustomAnalyserProvided_reflectsMergedValues() {
    ClientGetState state = new ClientGetState(new ClientGet());
    FcpCompatibilityAnalysis analyser = new FcpCompatibilityAnalysis();
    byte[] splitfileKey = new byte[] {1, 2, 3, 4};
    analyser.merge(
        FcpCompatibilityMode.COMPAT_1250,
        FcpCompatibilityMode.COMPAT_1468,
        splitfileKey,
        true,
        false);

    state.setCompatibilityAnalyser(analyser);

    assertSame(analyser, state.getCompatibilityAnalyser());
    assertArrayEquals(
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
        },
        state.getCompatibilityMode());
    assertTrue(state.getDontCompress());
    assertArrayEquals(splitfileKey, state.getOverriddenSplitfileCryptoKey());
  }

  @Test
  void ensureCompatibilityMode_whenAnalyserMissing_createsNewInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    state.setCompatibilityAnalyser(null);

    state.ensureCompatibilityMode();

    assertNotNull(state.getCompatibilityAnalyser());
  }

  @Test
  void ensureCompatibilityMode_whenAnalyserPresent_keepsSameInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    FcpCompatibilityAnalysis analyser = state.getCompatibilityAnalyser();

    state.ensureCompatibilityMode();

    assertSame(analyser, state.getCompatibilityAnalyser());
  }

  @Test
  void resetCompatibilityMode_whenInvoked_replacesAnalyserInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    FcpCompatibilityAnalysis before = state.getCompatibilityAnalyser();

    state.resetCompatibilityMode();

    assertNotNull(state.getCompatibilityAnalyser());
    assertNotSame(before, state.getCompatibilityAnalyser());
  }

  @Test
  void deserializeLegacyState_whenCompatibilityAnalyserSerialized_migratesDetachedAnalysis(
      @TempDir Path tempDir) throws Exception {
    ClientGetState restored = deserializeLegacyClientGetState(tempDir);
    FcpCompatibilityAnalysis compatibilityAnalysis = restored.getCompatibilityAnalyser();

    assertInstanceOf(FcpCompatibilityAnalysis.class, getCompatModeField(restored));
    assertArrayEquals(
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
        },
        restored.getCompatibilityMode());
    assertFalse(restored.getDontCompress());
    assertArrayEquals(new byte[] {1, 2, 3, 4}, restored.getOverriddenSplitfileCryptoKey());
    assertTrue(compatibilityAnalysis.definitive());
  }

  @Test
  void mergeCompatibilityMode_whenNoClientAndNoVerbosity_updatesAnalyserWithoutQueueing() {
    ClientGet request = spy(new ClientGet());
    ClientGetState state = new ClientGetState(request);
    byte[] splitfileKey = new byte[] {9, 8, 7};

    state.mergeCompatibilityMode(
        FcpCompatibilityMode.COMPAT_1250,
        FcpCompatibilityMode.COMPAT_1468,
        splitfileKey,
        false,
        false);

    assertArrayEquals(
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
        },
        state.getCompatibilityMode());
    assertArrayEquals(splitfileKey, state.getOverriddenSplitfileCryptoKey());
    assertFalse(state.getDontCompress());
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void mergeCompatibilityMode_whenClientAndVerbosityPresent_updatesCacheAndQueuesMessage()
      throws Exception {
    ClientGet request = spy(new ClientGet());
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetState state = new ClientGetState(request);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "identifier", "req-compat");
    setClientRequestField(request, "global", true);
    setClientRequestField(request, "verbosity", ClientGet.VERBOSITY_COMPATIBILITY_MODE);
    byte[] splitfileKey = new byte[] {3, 1, 4};

    state.mergeCompatibilityMode(
        FcpCompatibilityMode.COMPAT_1250,
        FcpCompatibilityMode.COMPAT_1468,
        splitfileKey,
        true,
        false);

    ArgumentCaptor<FcpCompatibilityMode[]> modesCaptor =
        ArgumentCaptor.forClass(FcpCompatibilityMode[].class);
    verify(cache)
        .updateDetectedCompatModes(
            eq("req-compat"), modesCaptor.capture(), eq(splitfileKey), eq(true));
    assertArrayEquals(
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
        },
        modesCaptor.getValue());
    verify(request)
        .queueProgressMessageInner(
            any(network.crypta.clients.fcp.CompatibilityMode.class),
            eq(ClientGet.VERBOSITY_COMPATIBILITY_MODE));
  }

  @Test
  void mergeCompatibilityMode_whenClientCacheMissing_skipsCacheUpdateAndQueueWhenVerbosityOff()
      throws Exception {
    ClientGet request = spy(new ClientGet());
    ClientGetState state = new ClientGetState(request);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    when(client.getRequestStatusCache()).thenReturn(null);
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "identifier", "req-no-cache");
    setClientRequestField(request, "verbosity", 0);

    state.mergeCompatibilityMode(
        FcpCompatibilityMode.COMPAT_1250,
        FcpCompatibilityMode.COMPAT_1468,
        new byte[] {5},
        false,
        false);

    verify(client).getRequestStatusCache();
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void returnBucketDirect_whenSetGetAndTake_clearsAfterTake() {
    ClientGetState state = new ClientGetState(new ClientGet());
    Bucket bucket = mock(Bucket.class);
    state.setReturnBucketDirect(bucket);

    assertSame(bucket, state.getReturnBucketDirect());
    assertSame(bucket, state.takeReturnBucketDirect());
    assertNull(state.getReturnBucketDirect());
    assertNull(state.takeReturnBucketDirect());
  }

  @SuppressWarnings({"java:S3011"})
  private static void setClientRequestField(ClientRequest target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings({"java:S3011"})
  private static Object getCompatModeField(ClientGetState state)
      throws ReflectiveOperationException {
    Field field = ClientGetState.class.getDeclaredField("compatMode");
    field.setAccessible(true);
    return field.get(state);
  }

  private static ClientGetState deserializeLegacyClientGetState(Path tempDir) throws Exception {
    compileLegacyClientGetState(tempDir);
    Path classesRoot = tempDir.resolve("legacy-classes");
    try (URLClassLoader classLoader =
        new ChildFirstClientGetStateClassLoader(
            classesRoot.toUri().toURL(), ClientGetState.class.getClassLoader())) {
      Class<?> legacyStateClass =
          Class.forName("network.crypta.clients.fcp.ClientGetState", true, classLoader);
      Object legacyState = legacyStateClass.getDeclaredConstructor().newInstance();
      ByteArrayOutputStream serialized = new ByteArrayOutputStream();
      try (ObjectOutputStream out = new ObjectOutputStream(serialized)) {
        out.writeObject(legacyState);
      }
      try (ObjectInputStream in =
          new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray()))) {
        return (ClientGetState) in.readObject();
      }
    }
  }

  private static void compileLegacyClientGetState(Path tempDir) throws Exception {
    Path sourceRoot = tempDir.resolve("legacy-src");
    Path classesRoot = tempDir.resolve("legacy-classes");
    Path sourceFile = sourceRoot.resolve("network/crypta/clients/fcp/ClientGetState.java");
    Files.createDirectories(sourceFile.getParent());
    Files.createDirectories(classesRoot);
    Files.writeString(sourceFile, legacyClientGetStateSource());
    ByteArrayOutputStream compilerOutput = new ByteArrayOutputStream();
    int rc =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                compilerOutput,
                compilerOutput,
                "-classpath",
                System.getProperty("java.class.path"),
                "-d",
                classesRoot.toString(),
                sourceFile.toString());
    if (rc != 0) {
      throw new IllegalStateException(
          "javac failed for legacy ClientGetState: rc="
              + rc
              + System.lineSeparator()
              + compilerOutput);
    }
  }

  private static String legacyClientGetStateSource() {
    return """
    package network.crypta.clients.fcp;

    import java.io.Serial;
    import java.io.Serializable;
    import network.crypta.client.InsertContext.CompatibilityMode;
    import network.crypta.client.async.CompatibilityAnalyser;

    public final class ClientGetState implements Serializable {
      @Serial private static final long serialVersionUID = 1L;

      CompatibilityAnalyser compatMode;

      public ClientGetState() {
        compatMode = new CompatibilityAnalyser();
        compatMode.merge(
            CompatibilityMode.COMPAT_1250,
            CompatibilityMode.COMPAT_1468,
            new byte[] {1, 2, 3, 4},
            false,
            true);
      }
    }
    """;
  }

  private static final class ChildFirstClientGetStateClassLoader extends URLClassLoader {
    private static final String LEGACY_CLIENT_GET_STATE_CLASS =
        "network.crypta.clients.fcp.ClientGetState";

    private ChildFirstClientGetStateClassLoader(URL url, ClassLoader parent) {
      super(new URL[] {url}, parent);
    }

    @Override
    protected synchronized Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException {
      if (name.equals(LEGACY_CLIENT_GET_STATE_CLASS)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          loaded = findClass(name);
        }
        if (resolve) {
          resolveClass(loaded);
        }
        return loaded;
      }
      return super.loadClass(name, resolve);
    }
  }
}

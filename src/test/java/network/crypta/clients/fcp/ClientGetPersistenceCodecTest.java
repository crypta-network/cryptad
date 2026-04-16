package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import javax.tools.ToolProvider;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.withSettings;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetPersistenceCodecTest {
  private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
  private static final int CLIENT_DETAIL_VERSION = 1;

  @Test
  void readBasicRestoreData_whenValidDiskData_returnsParsedBundle() throws Exception {
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setFilterData(true);
    Bucket initialMetadata = mock(Bucket.class);
    try (DataInputStream input = input(basicRestoreHeaderPayload());
        MockedStatic<ClientGetPersistenceIO> mocked =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      mocked
          .when(
              () ->
                  ClientGetPersistenceIO.readFetchConfigOrDefault(
                      input, fetchRuntimeSupport, checker))
          .thenReturn(fetchConfig);
      mocked
          .when(
              () -> ClientGetPersistenceIO.readInitialMetadata(input, fetchRuntimeSupport, checker))
          .thenReturn(initialMetadata);

      ClientGetPersistenceCodec.BasicRestoreData restored =
          ClientGetPersistenceCodec.readBasicRestoreData(input, fetchRuntimeSupport, checker);

      assertEquals("KSK@codec-restore", restored.uri().toString());
      assertEquals(ClientGet.ReturnType.DISK, restored.returnType());
      assertEquals("target.bin", restored.targetFile().getPath());
      assertTrue(restored.binaryBlob());
      assertEquals(fetchConfig, restored.fetchConfig());
      assertEquals("txt", restored.extensionCheck());
      assertSame(initialMetadata, restored.initialMetadata());
    }
  }

  @Test
  void readBasicRestoreData_whenMagicIsInvalid_throwsStorageFormatException() throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(123L);
      out.writeInt(CLIENT_DETAIL_VERSION);
    }
    try (DataInputStream input = input(buffer.toByteArray())) {
      StorageFormatException error =
          assertThrows(
              StorageFormatException.class,
              () ->
                  ClientGetPersistenceCodec.readBasicRestoreData(
                      input, mock(FcpFetchRuntimeSupport.class), mock(ChecksumChecker.class)));

      assertEquals("Bad magic for request", error.getMessage());
    }
  }

  @Test
  void readTransientProgressFields_whenExplicitIdentifier_updatesStateAndExpectedHashes()
      throws Exception {
    ClientGet request = new ClientGet();
    ExpectedHashes expected = new ExpectedHashes(new HashResult[0], "req-explicit", true);
    try (DataInputStream input = input(transientPayload(42L, "text/plain"));
        MockedStatic<ClientGetGetterFactory> mocked =
            Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(() -> ClientGetGetterFactory.readExpectedHashes(input, "req-explicit", true))
          .thenReturn(expected);

      ClientGetPersistenceCodec.readTransientProgressFields(request, input, "req-explicit", true);

      assertEquals(42L, request.state().getFoundDataLength());
      assertEquals("text/plain", request.state().getFoundDataMimeType());
      assertSame(expected, request.state().getExpectedHashes());
      assertNotNull(request.state().getCompatibilityAnalyser());
    }
  }

  @Test
  void restoreState_whenInProgress_returnsExecutionAndDelegatesRestore() throws Exception {
    ClientGet request = Mockito.spy(new ClientGet());
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(false, "client", "req-restore", RequestIdentifier.RequestType.GET);
    Bucket bucket = mock(Bucket.class);
    ClientGetExecution execution = mock(ClientGetExecution.class);
    //noinspection resource
    doReturn(bucket).when(request).makePersistenceBucket();
    doReturn(execution).when(request).makeExecutionForPersistence(bucket);

    try (DataInputStream input = input(new byte[0]);
        MockedStatic<ClientGetPersistenceIO> mocked =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      ClientGetExecution restored =
          ClientGetPersistenceCodec.restoreState(
              request, input, reqID, fetchRuntimeSupport, checker);

      assertSame(execution, restored);
      mocked.verify(
          () ->
              ClientGetPersistenceIO.restoreInProgressState(
                  any(DataInputStream.class),
                  eq(fetchRuntimeSupport),
                  eq(checker),
                  eq(execution),
                  eq(request)),
          times(1));
    }
  }

  @Test
  void restoreState_whenFinishedDirectAndBucketMissing_marksRequestUnfinished() throws Exception {
    ClientGet request = finishedDirectRequest();
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(
            false, "client", "req-finished-direct", RequestIdentifier.RequestType.GET);

    try (DataInputStream input = input(finishedPayload(transientPayload(55L, null)));
        MockedStatic<ClientGetGetterFactory> mockedGetterFactory =
            Mockito.mockStatic(ClientGetGetterFactory.class);
        MockedStatic<ClientGetPersistenceIO> mockedPersistenceIO =
            Mockito.mockStatic(ClientGetPersistenceIO.class)) {
      mockedGetterFactory
          .when(() -> ClientGetGetterFactory.readExpectedHashes(any(), any(), anyBoolean()))
          .thenReturn(null);
      mockedPersistenceIO
          .when(
              () ->
                  ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(
                      any(DataInputStream.class), eq(fetchRuntimeSupport), eq(checker)))
          .thenReturn(null);

      ClientGetExecution restored =
          ClientGetPersistenceCodec.restoreState(
              request, input, reqID, fetchRuntimeSupport, checker);

      assertNull(restored);
      assertFalse(isFinished(request));
      assertFalse(request.state().hasSucceeded());
      assertNull(request.state().getReturnBucketDirect());
    }
  }

  @Test
  void serializedRequest_whenRuntimeFetchSupportPresent_cachesFetchConfigEncoding()
      throws Exception {
    ClientGet request = persistenceReadyRequest();
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    byte[] encodedFetchConfig = new byte[] {4, 5, 6};
    Mockito.doAnswer(
            invocation -> {
              DataOutputStream encoded = invocation.getArgument(1);
              encoded.write(encodedFetchConfig);
              return null;
            })
        .when(fetchRuntimeSupport)
        .encodeFetchConfig(eq(request.requestProfile().fetchConfig()), any(DataOutputStream.class));
    ClientGetTestProfiles.setRuntimeFetchSupport(request, fetchRuntimeSupport);

    ClientGet restored = serializeAndDeserialize(request);

    assertArrayEquals(encodedFetchConfig, restored.persistedFetchConfigEncoding());
  }

  @Test
  void deserializeLegacySerializedRequest_whenRequestProfileMissing_reconstructsLegacyValues(
      @TempDir Path tempDir) throws Exception {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setFilterData(true);
    Bucket initialMetadata = mock(Bucket.class, withSettings().serializable());
    File targetFile = tempDir.resolve("legacy-target.bin").toFile();
    byte[] cachedEncoding = new byte[] {7, 8, 9};

    ClientGet restored =
        deserializeLegacySerializedRequest(
            tempDir, fetchConfig, targetFile, initialMetadata, cachedEncoding);

    assertNotNull(restored.requestProfile());
    assertNotNull(restored.requestProfile().fetchConfig());
    assertTrue(restored.requestProfile().fetchConfig().getFilterData());
    assertSame(ClientGet.ReturnType.DIRECT, restored.requestProfile().returnType());
    assertEquals(targetFile.getPath(), restored.requestProfile().targetFile().getPath());
    assertTrue(restored.requestProfile().binaryBlob());
    assertEquals("bin", restored.requestProfile().extensionCheck());
    assertNotNull(restored.requestProfile().initialMetadata());
    assertNotNull(restored.state());
    assertNotNull(restored.persistenceLock());
    assertArrayEquals(cachedEncoding, restored.persistedFetchConfigEncoding());
  }

  @Test
  void writeClientDetail_whenRuntimeFetchSupportMissing_usesCachedFetchConfigEncoding()
      throws Exception {
    ClientGet request = persistenceReadyRequest();
    ClientGetExecution execution = mock(ClientGetExecution.class);
    byte[] cachedEncoding = new byte[] {1, 2, 3};
    setField(request, ClientGet.class, "execution", execution);
    request.setPersistedFetchConfigEncoding(cachedEncoding);
    Mockito.when(execution.writeTrivialProgress(any(DataOutputStream.class))).thenReturn(false);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream encodedFetchConfig = new ByteArrayOutputStream();
    AtomicInteger checksummedWriterCalls = new AtomicInteger();

    try (MockedStatic<ClientGetGetterFactory> mocked =
        Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.checksummedWriter(
                      any(DataOutputStream.class), eq(checker)))
          .thenAnswer(
              _ ->
                  new DataOutputStream(
                      checksummedWriterCalls.getAndIncrement() == 0
                          ? encodedFetchConfig
                          : new ByteArrayOutputStream()));

      ClientGetPersistenceCodec.writeClientDetail(
          request, new DataOutputStream(new ByteArrayOutputStream()), checker);
    }

    assertArrayEquals(cachedEncoding, encodedFetchConfig.toByteArray());
    Mockito.verify(execution).writeTrivialProgress(any(DataOutputStream.class));
  }

  @Test
  void writeClientDetail_whenClientRootProvidesRuntimeSupport_encodesFetchConfig()
      throws Exception {
    ClientGet request = persistenceReadyRequest();
    ClientGetExecution execution = mock(ClientGetExecution.class);
    FcpFetchRuntimeSupport fetchRuntimeSupport = mock(FcpFetchRuntimeSupport.class);
    byte[] encodedFetchConfig = new byte[] {9, 8, 7};
    PersistentRequestRoot root = new PersistentRequestRoot();
    root.setFetchRuntimeSupport(fetchRuntimeSupport);
    PersistentRequestClient client = root.registerForeverClient("persist-client", null);
    setField(request, ClientRequest.class, "client", client);
    setField(request, ClientGet.class, "execution", execution);
    Mockito.doAnswer(
            invocation -> {
              DataOutputStream encoded = invocation.getArgument(1);
              encoded.write(encodedFetchConfig);
              return null;
            })
        .when(fetchRuntimeSupport)
        .encodeFetchConfig(eq(request.requestProfile().fetchConfig()), any(DataOutputStream.class));
    Mockito.when(execution.writeTrivialProgress(any(DataOutputStream.class))).thenReturn(false);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream capturedFetchConfig = new ByteArrayOutputStream();
    AtomicInteger checksummedWriterCalls = new AtomicInteger();

    try (MockedStatic<ClientGetGetterFactory> mocked =
        Mockito.mockStatic(ClientGetGetterFactory.class)) {
      mocked
          .when(
              () ->
                  ClientGetGetterFactory.checksummedWriter(
                      any(DataOutputStream.class), eq(checker)))
          .thenAnswer(
              _ ->
                  new DataOutputStream(
                      checksummedWriterCalls.getAndIncrement() == 0
                          ? capturedFetchConfig
                          : new ByteArrayOutputStream()));

      ClientGetPersistenceCodec.writeClientDetail(
          request, new DataOutputStream(new ByteArrayOutputStream()), checker);
    }

    assertArrayEquals(encodedFetchConfig, capturedFetchConfig.toByteArray());
    assertArrayEquals(encodedFetchConfig, request.persistedFetchConfigEncoding());
    Mockito.verify(fetchRuntimeSupport)
        .encodeFetchConfig(eq(request.requestProfile().fetchConfig()), any());
  }

  private static ClientGet finishedDirectRequest() throws Exception {
    ClientGet request = new ClientGet();
    setField(request, ClientRequest.class, "identifier", "req-finished-direct");
    setField(request, ClientRequest.class, "global", false);
    setField(request, ClientRequest.class, "finished", true);
    ClientGetTestProfiles.setReturnType(request, ClientGet.ReturnType.DIRECT);
    request.state().setSucceeded(true);
    return request;
  }

  private static ClientGet persistenceReadyRequest() throws Exception {
    ClientGet request = new ClientGet();
    setField(request, ClientRequest.class, "identifier", "req-persist");
    setField(request, ClientRequest.class, "global", false);
    setField(request, ClientRequest.class, "uri", new FreenetURI("KSK@persist"));
    ClientGetTestProfiles.setFetchConfig(request, new ClientGetFetchConfig());
    ClientGetTestProfiles.setReturnType(request, ClientGet.ReturnType.DIRECT);
    return request;
  }

  private static ClientGet serializeAndDeserialize(ClientGet request) throws Exception {
    ByteArrayOutputStream serialized = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(serialized)) {
      out.writeObject(request);
    }
    try (ObjectInputStream in =
        new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray()))) {
      return (ClientGet) in.readObject();
    }
  }

  private static DataInputStream input(byte[] payload) {
    return new DataInputStream(new ByteArrayInputStream(payload));
  }

  private static ClientGet deserializeLegacySerializedRequest(
      Path tempDir,
      ClientGetFetchConfig fetchConfig,
      File targetFile,
      Bucket initialMetadata,
      byte[] cachedEncoding)
      throws Exception {
    compileLegacyClientGet(tempDir);
    Path classesRoot = tempDir.resolve("legacy-classes");
    try (URLClassLoader classLoader =
        new ChildFirstClientGetClassLoader(
            classesRoot.toUri().toURL(), ClientGet.class.getClassLoader())) {
      Class<?> legacyClientGetClass =
          Class.forName("network.crypta.clients.fcp.ClientGet", true, classLoader);
      Object legacyClientGet = legacyClientGetClass.getDeclaredConstructor().newInstance();
      setLegacyField(legacyClientGetClass, legacyClientGet, "fetchConfig", fetchConfig);
      setLegacyField(
          legacyClientGetClass, legacyClientGet, "returnType", legacyReturnType(classLoader));
      setLegacyField(legacyClientGetClass, legacyClientGet, "targetFile", targetFile);
      setLegacyField(legacyClientGetClass, legacyClientGet, "binaryBlob", true);
      setLegacyField(legacyClientGetClass, legacyClientGet, "extensionCheck", "bin");
      setLegacyField(legacyClientGetClass, legacyClientGet, "initialMetadata", initialMetadata);
      setLegacyField(
          legacyClientGetClass, legacyClientGet, "persistedFetchConfigEncoding", cachedEncoding);

      ByteArrayOutputStream serialized = new ByteArrayOutputStream();
      try (ObjectOutputStream out = new ObjectOutputStream(serialized)) {
        out.writeObject(legacyClientGet);
      }
      try (ObjectInputStream in =
          new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray()))) {
        return (ClientGet) in.readObject();
      }
    }
  }

  private static void compileLegacyClientGet(Path tempDir) throws IOException {
    Path sourceRoot = tempDir.resolve("legacy-src");
    Path classesRoot = tempDir.resolve("legacy-classes");
    Path sourceFile = sourceRoot.resolve("network/crypta/clients/fcp/ClientGet.java");
    Files.createDirectories(sourceFile.getParent());
    Files.createDirectories(classesRoot);
    Files.writeString(sourceFile, legacyClientGetSource());
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
      throw new IOException(
          "javac failed for legacy ClientGet: rc=" + rc + System.lineSeparator() + compilerOutput);
    }
  }

  private static String legacyClientGetSource() {
    return """
    package network.crypta.clients.fcp;

    import java.io.File;
    import java.io.Serial;
    import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
    import network.crypta.support.api.Bucket;
    import network.crypta.support.io.ResumeFailedException;

    public final class ClientGet extends ClientRequest {
      @Serial private static final long serialVersionUID = 1L;

      ClientGetFetchConfig fetchConfig;
      ClientGetExecution execution;
      ReturnType returnType;
      File targetFile;
      boolean binaryBlob;
      String extensionCheck;
      Bucket initialMetadata;
      byte[] persistedFetchConfigEncoding;

      public enum ReturnType {
        DIRECT((short) 0),
        NONE((short) 1),
        DISK((short) 2),
        CHUNKED((short) 3);

        final short code;

        ReturnType(short code) {
          this.code = code;
        }
      }

      public ClientGet() {
        super();
      }

      @Override
      public void onLostConnection(PersistentRequestRuntimeContext context) {}

      @Override
      public void sendPendingMessages(
          FCPConnectionOutputHandler handler,
          String listRequestIdentifier,
          boolean includeData,
          boolean onlyData) {}

      @Override
      void register(boolean noTags) {}

      @Override
      public void start(PersistentRequestRuntimeContext context) {}

      @Override
      protected FcpRequesterHandle getClientRequest() {
        return null;
      }

      @Override
      protected void freeData() {}

      @Override
      public double getSuccessFraction() {
        return 0;
      }

      @Override
      public double getTotalBlocks() {
        return 0;
      }

      @Override
      public double getMinBlocks() {
        return 0;
      }

      @Override
      public double getFetchedBlocks() {
        return 0;
      }

      @Override
      public double getFailedBlocks() {
        return 0;
      }

      @Override
      public double getFatalyFailedBlocks() {
        return 0;
      }

      @Override
      public String getFailureReason(boolean longDescription) {
        return null;
      }

      @Override
      public boolean isTotalFinalized() {
        return false;
      }

      @Override
      public boolean hasSucceeded() {
        return false;
      }

      @Override
      public boolean canRestart() {
          return false;
        }

          @Override
          public boolean restart(
              PersistentRequestRuntimeContext context, boolean disableFilterData) {
            return false;
          }

          @Override
          public boolean fullyResumed() {
            return false;
          }

          @Override
          RequestStatus getStatus() {
            return null;
          }

      @Override
      protected void innerResume(FcpRequestRuntimeContext context) throws ResumeFailedException {}

      @Override
      RequestIdentifier.RequestType getType() {
        return RequestIdentifier.RequestType.GET;
      }
    }
    """;
  }

  private static byte[] basicRestoreHeaderPayload() throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(CLIENT_DETAIL_MAGIC);
      out.writeInt(CLIENT_DETAIL_VERSION);
      out.writeUTF("KSK@codec-restore");
      out.writeShort(ClientGet.ReturnType.DISK.code);
      out.writeUTF("target.bin");
      out.writeBoolean(true);
      out.writeBoolean(true);
      out.writeUTF("txt");
      out.writeBoolean(false);
    }
    return buffer.toByteArray();
  }

  private static byte[] transientPayload(long dataLength, String mimeType) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(dataLength);
      out.writeBoolean(mimeType != null);
      if (mimeType != null) {
        out.writeUTF(mimeType);
      }
      new FcpCompatibilityAnalysis().writeTo(out);
      out.writeInt(0);
    }
    return buffer.toByteArray();
  }

  private static byte[] finishedPayload(byte[] transientPayload) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeBoolean(true);
      out.write(transientPayload);
    }
    return buffer.toByteArray();
  }

  private static void setField(Object target, Class<?> owner, String fieldName, Object value)
      throws Exception {
    Field field = owner.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static void setLegacyField(Class<?> owner, Object target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static Object legacyReturnType(ClassLoader classLoader) throws ClassNotFoundException {
    Class<? extends Enum> legacyReturnType =
        Class.forName("network.crypta.clients.fcp.ClientGet$ReturnType", true, classLoader)
            .asSubclass(Enum.class);
    return Enum.valueOf((Class) legacyReturnType, "DIRECT");
  }

  private static boolean isFinished(ClientGet request) throws Exception {
    Field field = ClientRequest.class.getDeclaredField("finished");
    field.setAccessible(true);
    return field.getBoolean(request);
  }

  private static final class ChildFirstClientGetClassLoader extends URLClassLoader {
    private static final String LEGACY_CLIENT_GET_CLASS = "network.crypta.clients.fcp.ClientGet";

    private ChildFirstClientGetClassLoader(URL url, ClassLoader parent) {
      super(new URL[] {url}, parent);
    }

    @Override
    protected synchronized Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException {
      if (name.equals(LEGACY_CLIENT_GET_CLASS) || name.startsWith(LEGACY_CLIENT_GET_CLASS + "$")) {
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

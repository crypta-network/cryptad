package network.crypta.client.async;

import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.NullClientCallback;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PlainManifestPutterTest {

  private static InsertContext newInsertContextCurrent() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(1, 0)
            .splitfileSegmentLimits(128, 128)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(network.crypta.client.InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  // Helper to create a bucket with a specific size
  private static RandomAccessBucket bucketWithBytes(int size) throws Exception {
    ArrayBucket b = new ArrayBucket();
    try (OutputStream os = b.getOutputStream()) {
      os.write(new byte[size]);
    }
    return b;
  }

  @Test
  void constructor_whenFreeformElements_expectCountsAndSizesAggregated() throws Exception {
    // Arrange
    RandomAccessBucket b10 = bucketWithBytes(10);
    RandomAccessBucket b20 = bucketWithBytes(20);

    Map<String, Object> root = getStringObjectHashMap(b10, b20);

    RequestClient requestClient = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(requestClient);
    InsertContext ctx = newInsertContextCurrent();

    // Force a deterministic crypto key so ClientContext.random isn't used
    byte[] forceKey = new byte[32];

    // Act
    PlainManifestPutter putter =
        new PlainManifestPutter(
            new ManifestPutterParams(
                new InsertRequestParams(cb, FreenetURI.EMPTY_CHK_URI, ctx, /*prioClass*/ (short) 0),
                root,
                /*defaultName*/ "index.html",
                forceKey,
                /*context*/ mock(ClientContext.class)));

    // Assert
    assertEquals(2, putter.countFiles(), "counts only external data elements");
    assertEquals(30, putter.totalSize(), "sums sizes of external data buckets");
  }

  private static @NotNull Map<String, Object> getStringObjectHashMap(
      RandomAccessBucket b10, RandomAccessBucket b20) {
    ManifestElement eIndex = new ManifestElement("index.html", b10, "text/html", 10);
    ManifestElement eReadme = new ManifestElement("readme.txt", b20, "text/plain", 20);
    ManifestElement eRedirect =
        new ManifestElement("link", new FreenetURI("KSK", "some-doc"), null);

    HashMap<String, Object> root = new HashMap<>();
    HashMap<String, Object> sub = new HashMap<>();
    sub.put("index.html", eIndex);
    root.put("sub", sub);
    root.put("readme.txt", eReadme);
    root.put("link", eRedirect);
    return root;
  }

  // Subclass to inject a mocked FreeFormBuilder for verifying recursion and adds
  private static class TestablePlainManifestPutter extends PlainManifestPutter {
    private FreeFormBuilder injected;

    TestablePlainManifestPutter(
        NullClientCallback cb,
        Map<String, Object> manifest,
        InsertContext ctx,
        byte[] forceKey,
        ClientContext context) {
      super(
          new ManifestPutterParams(
              new InsertRequestParams(cb, FreenetURI.EMPTY_CHK_URI, ctx, /*prioClass*/ (short) 0),
              manifest,
              /*defaultName*/ "index.html",
              forceKey,
              context));
    }

    void setInjectedBuilder(FreeFormBuilder b) {
      this.injected = b;
    }

    @Override
    protected FreeFormBuilder getRootBuilder() {
      if (injected != null) return injected;
      return super.getRootBuilder();
    }
  }

  @Test
  @SuppressWarnings("java:S125")
  void makePutHandlers_whenNestedTree_expectBuilderDirOpsAndAddsCalled() throws Exception {
    // Arrange manifest: { dir: { index.html }, readme.txt }
    RandomAccessBucket b10 = bucketWithBytes(10);
    RandomAccessBucket b20 = bucketWithBytes(20);

    ManifestElement eIndex = new ManifestElement("index.html", b10, "text/html", 10);
    ManifestElement eReadme = new ManifestElement("readme.txt", b20, "text/plain", 20);

    HashMap<String, Object> root = new HashMap<>();
    HashMap<String, Object> sub = new HashMap<>();
    sub.put("index.html", eIndex);
    root.put("dir", sub);
    root.put("readme.txt", eReadme);

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();
    byte[] forceKey = new byte[32];

    // Use an empty manifest at construction to avoid interfering with our injected builder call
    TestablePlainManifestPutter putter =
        new TestablePlainManifestPutter(
            cb, new HashMap<>(), ctx, forceKey, mock(ClientContext.class));

    // Mock a FreeFormBuilder tied to this outer instance so Mockito can create the inner-class mock
    BaseManifestPutter.FreeFormBuilder builder =
        Mockito.mock(
            BaseManifestPutter.FreeFormBuilder.class,
            Mockito.withSettings()
                .useConstructor()
                .outerInstance(putter)
                .defaultAnswer(Answers.RETURNS_DEFAULTS));
    putter.setInjectedBuilder(builder);

    // Act: invoke the protected method under test directly
    putter.makePutHandlers(root, "index.html");

    // Assert: directory navigation for the subdir and two adding (default doc in subdir only)
    verify(builder, times(1)).pushCurrentDir();
    verify(builder, times(1)).makeSubDirCD("dir");
    verify(builder, times(1)).popCurrentDir();

    verify(builder, times(1)).addElement(eq("index.html"), same(eIndex), eq(true));
    verify(builder, times(1)).addElement(eq("readme.txt"), same(eReadme), eq(false));
  }

  @Test
  @SuppressWarnings("java:S125")
  void makePutHandlers_whenNestedImmutableMap_expectBuilderDirOpsAndAddsCalled() throws Exception {
    // Arrange manifest: { dir: Map.of("index.html", eIndex), readme.txt }
    RandomAccessBucket b10 = bucketWithBytes(10);
    RandomAccessBucket b20 = bucketWithBytes(20);

    ManifestElement eIndex = new ManifestElement("index.html", b10, "text/html", 10);
    ManifestElement eReadme = new ManifestElement("readme.txt", b20, "text/plain", 20);

    HashMap<String, Object> root = new HashMap<>();
    root.put("dir", java.util.Map.of("index.html", eIndex));
    root.put("readme.txt", eReadme);

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();
    byte[] forceKey = new byte[32];

    TestablePlainManifestPutter putter =
        new TestablePlainManifestPutter(
            cb, new HashMap<>(), ctx, forceKey, mock(ClientContext.class));

    BaseManifestPutter.FreeFormBuilder builder =
        Mockito.mock(
            BaseManifestPutter.FreeFormBuilder.class,
            Mockito.withSettings()
                .useConstructor()
                .outerInstance(putter)
                .defaultAnswer(Answers.RETURNS_DEFAULTS));
    putter.setInjectedBuilder(builder);

    // Act
    putter.makePutHandlers(root, "index.html");

    // Assert: should treat Map.of as a subdirectory, not as a ManifestElement
    verify(builder, times(1)).pushCurrentDir();
    verify(builder, times(1)).makeSubDirCD("dir");
    verify(builder, times(1)).popCurrentDir();

    verify(builder, times(1)).addElement(eq("index.html"), same(eIndex), eq(true));
    verify(builder, times(1)).addElement(eq("readme.txt"), same(eReadme), eq(false));
  }

  @Test
  void makePutHandlers_whenInvalidElement_throwsClassCastException() {
    // Arrange
    HashMap<String, Object> root = new HashMap<>();
    root.put("bad", 123); // not a HashMap nor ManifestElement

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();
    byte[] forceKey = new byte[32];

    TestablePlainManifestPutter putter =
        new TestablePlainManifestPutter(
            cb, new HashMap<>(), ctx, forceKey, mock(ClientContext.class));

    // Inject a no-op builder to satisfy getRootBuilder during the call
    BaseManifestPutter.FreeFormBuilder builder =
        Mockito.mock(
            BaseManifestPutter.FreeFormBuilder.class,
            Mockito.withSettings()
                .useConstructor()
                .outerInstance(putter)
                .defaultAnswer(Answers.RETURNS_DEFAULTS));
    putter.setInjectedBuilder(builder);

    // Act + Assert
    assertThrows(ClassCastException.class, () -> putter.makePutHandlers(root, "index.html"));
  }

  @Test
  void innerOnResume_whenCalled_expectNotifyClientsQueued() throws Exception {
    // Arrange
    RequestClient persistentClient = new RequestClientBuilder().persistent().build();
    NullClientCallback cb = new NullClientCallback(persistentClient);
    InsertContext ctx = newInsertContextCurrent();
    byte[] forceKey = new byte[32];

    PlainManifestPutter putter =
        new PlainManifestPutter(
            new ManifestPutterParams(
                new InsertRequestParams(cb, FreenetURI.EMPTY_CHK_URI, ctx, /*prioClass*/ (short) 0),
                new HashMap<>(),
                /*defaultName*/ "index.html",
                forceKey,
                mock(ClientContext.class)));

    // We expect notifyClients() to call getJobRunner(true).queueNormalOrDrop(...)
    ClientContext context = mock(ClientContext.class);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    doNothing().when(jobRunner).queueNormalOrDrop(any());
    when(context.getJobRunner(true)).thenReturn(jobRunner);

    // Act
    putter.innerOnResume(context);

    // Assert
    verify(context, times(1)).getJobRunner(true);
    verify(jobRunner, times(1)).queueNormalOrDrop(any());
  }
}

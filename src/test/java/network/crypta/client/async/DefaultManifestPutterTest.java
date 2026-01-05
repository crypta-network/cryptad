package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.NullClientCallback;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DefaultManifestPutterTest {

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
  void constructor_whenUnknownElementType_throwsIllegalArgumentException() {
    // Arrange: manifest with an unsupported value type
    HashMap<String, Object> root = new HashMap<>();
    root.put("bad", 123);

    RequestClient requestClient = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(requestClient);
    InsertContext ctx = newInsertContextCurrent();

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new DefaultManifestPutter(
                cb,
                root,
                /*prioClass*/ (short) 0,
                FreenetURI.EMPTY_CHK_URI,
                /*defaultName*/ "index.html",
                ctx,
                /*persistent*/ false,
                /*forceCryptoKey*/ null,
                /*context*/ mock(ClientContext.class)));
  }

  // A subclass that lets us spy on the builders created during packing
  private static class TestableDefaultManifestPutter extends DefaultManifestPutter {
    BaseManifestPutter.ContainerBuilder rootSpy;

    // We return a spy from makeArchive() so we can verify addArchiveItem() calls

    TestableDefaultManifestPutter(
        NullClientCallback cb,
        HashMap<String, Object> manifest,
        short prio,
        FreenetURI target,
        String defaultName,
        InsertContext ctx,
        boolean persistent,
        byte[] forceKey,
        ClientContext context)
        throws TooManyFilesInsertException {
      super(cb, manifest, prio, target, defaultName, ctx, persistent, forceKey, context);
    }

    @Override
    protected BaseManifestPutter.ContainerBuilder getRootContainer() {
      BaseManifestPutter.ContainerBuilder real = super.getRootContainer();
      BaseManifestPutter.ContainerBuilder spy = Mockito.spy(real);
      rootSpy = spy;
      return spy;
    }

    @Override
    protected BaseManifestPutter.ContainerBuilder makeArchive() {
      BaseManifestPutter.ContainerBuilder real = super.makeArchive();
      return Mockito.spy(real);
    }
  }

  @Test
  void makePutHandlers_allFitsUnlimited_putsAllAsItemsAndCounts() throws Exception {
    // Arrange
    RandomAccessBucket b10 = bucketWithBytes(10);
    RandomAccessBucket b20 = bucketWithBytes(20);
    ManifestElement eIndex = new ManifestElement("index.html", b10, "text/html", 10);
    ManifestElement eStyle = new ManifestElement("style.css", b20, "text/css", 20);

    HashMap<String, Object> root = new HashMap<>();
    root.put("index.html", eIndex);
    root.put("style.css", eStyle);

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();

    TestableDefaultManifestPutter putter =
        new TestableDefaultManifestPutter(
            cb,
            root,
            /*prio*/ (short) 0,
            FreenetURI.EMPTY_CHK_URI,
            /*defaultName*/ "index.html",
            ctx,
            /*persistent*/ false,
            /*forceKey*/ null,
            /*context*/ mock(ClientContext.class));

    // Assert: two items added, default document shortlink added
    verify(putter.rootSpy, times(1))
        .addItem(eq("index.html"), eq("index.html"), any(ManifestElement.class), eq(true));
    verify(putter.rootSpy, times(1))
        .addItem(eq("style.css"), eq("style.css"), any(ManifestElement.class), eq(false));

    assertEquals(2, putter.countFiles(), "counts only data-backed elements");
    assertEquals(30, putter.totalSize(), "sums sizes of data buckets");

    // Inspect the constructed metadata map for the root container
    Map<String, Object> meta = getRootContainerMetadataMap(putter);
    assertNotNull(meta);
    Object idx = meta.get("index.html");
    Object sty = meta.get("style.css");
    Object def = meta.get("");
    assertNotNull(idx);
    assertNotNull(sty);
    assertNotNull(def);
    // Types: items are ManifestElement, default is a Metadata shortlink
    assertEquals(ManifestElement.class, idx.getClass());
    assertEquals(ManifestElement.class, sty.getClass());
    assertEquals(Metadata.class, def.getClass());
    // Access private field via reflection to verify shortlink type
    DocumentType dt1 = (DocumentType) readField(def, "documentType");
    assertEquals(DocumentType.SYMBOLIC_SHORTLINK, dt1);
  }

  @Test
  void makePutHandlers_limitedFitsWithLargeFile_marksLargeAsExternal() throws Exception {
    // Arrange: one small (<1MiB) and one big (>1MiB) file
    RandomAccessBucket small = bucketWithBytes(1024 * 1024 - 512); // tar item size ~= 1 MiB
    RandomAccessBucket big = bucketWithBytes(2 * 1024 * 1024); // > 1 MiB, will be external
    ManifestElement eSmall = new ManifestElement("index.html", small, "text/html", small.size());
    ManifestElement eBig = new ManifestElement("video.bin", big, null, big.size());

    HashMap<String, Object> root = new HashMap<>();
    root.put("index.html", eSmall);
    root.put("video.bin", eBig);

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();

    TestableDefaultManifestPutter putter =
        new TestableDefaultManifestPutter(
            cb,
            root,
            /*prio*/ (short) 0,
            FreenetURI.EMPTY_CHK_URI,
            /*defaultName*/ "index.html",
            ctx,
            /*persistent*/ false,
            /*forceKey*/ null,
            /*context*/ mock(ClientContext.class));

    // Assert: small file added in-container, big file added as external
    verify(putter.rootSpy, atLeastOnce())
        .addItem(eq("index.html"), eq("index.html"), any(ManifestElement.class), eq(true));
    verify(putter.rootSpy, atLeastOnce())
        .addExternal(
            eq("video.bin"),
            any(RandomAccessBucket.class),
            Mockito.<network.crypta.client.ClientMetadata>isNull(),
            eq(false));

    assertEquals(2, putter.countFiles());
    assertEquals(small.size() + big.size(), putter.totalSize());

    // Root manifest should not yet contain an entry for the external, only the default shortlink
    Map<String, Object> meta = getRootContainerMetadataMap(putter);
    assertFalse(meta.containsKey("video.bin"), "external not present until resolved");
    Object def = meta.get("");
    assertNotNull(def);
    assertEquals(Metadata.class, def.getClass());
    DocumentType dt2 = (DocumentType) readField(def, "documentType");
    assertEquals(DocumentType.SYMBOLIC_SHORTLINK, dt2);
  }

  @Test
  void makePutHandlers_itemsLeftTwoSmall_createsSingleArchiveAndAddsItems() throws Exception {
    // Arrange: one item just under 1MiB that fits, and two ~900KiB that won't fit -> itemsLeft=2
    RandomAccessBucket a = bucketWithBytes(1024 * 1024 - 512); // ~1MiB TAR item
    RandomAccessBucket b = bucketWithBytes(900_000);
    RandomAccessBucket c = bucketWithBytes(900_000);
    ManifestElement eA = new ManifestElement("A.bin", a, null, a.size());
    ManifestElement eB = new ManifestElement("B.bin", b, null, b.size());
    ManifestElement eC = new ManifestElement("C.bin", c, null, c.size());

    HashMap<String, Object> root = new HashMap<>();
    root.put("A.bin", eA);
    root.put("B.bin", eB);
    root.put("C.bin", eC);

    RequestClient rc = new RequestClientBuilder().build();
    NullClientCallback cb = new NullClientCallback(rc);
    InsertContext ctx = newInsertContextCurrent();

    TestableDefaultManifestPutter putter =
        new TestableDefaultManifestPutter(
            cb,
            root,
            /*prio*/ (short) 0,
            FreenetURI.EMPTY_CHK_URI,
            /*defaultName*/ "A.bin",
            ctx,
            /*persistent*/ false,
            /*forceKey*/ null,
            /*context*/ mock(ClientContext.class));

    // A is added as item, B and C are added to some archive (single or filled)
    verify(putter.rootSpy, atLeastOnce())
        .addItem(eq("A.bin"), eq("A.bin"), any(ManifestElement.class), eq(true));

    // Capture the archive add calls and assert names
    org.mockito.ArgumentCaptor<BaseManifestPutter.ContainerBuilder> arcCap =
        org.mockito.ArgumentCaptor.forClass(BaseManifestPutter.ContainerBuilder.class);
    org.mockito.ArgumentCaptor<String> nameCap = org.mockito.ArgumentCaptor.forClass(String.class);
    org.mockito.ArgumentCaptor<ManifestElement> meCap =
        org.mockito.ArgumentCaptor.forClass(ManifestElement.class);
    org.mockito.ArgumentCaptor<Boolean> defCap = org.mockito.ArgumentCaptor.forClass(Boolean.class);

    verify(putter.rootSpy, times(2))
        .addArchiveItem(arcCap.capture(), nameCap.capture(), meCap.capture(), defCap.capture());

    List<String> addedNames = nameCap.getAllValues();
    // order is not guaranteed; validate as a set
    java.util.Set<String> expected = new java.util.HashSet<>();
    expected.add("B.bin");
    expected.add("C.bin");
    java.util.Set<String> actual = new java.util.HashSet<>(addedNames);
    assertEquals(expected, actual, "archive contains B and C only");
  }

  @Test
  void innerOnResume_whenCalled_expectNotifyClientsQueued() throws Exception {
    // Arrange: persistent client so notifyClients uses the persistent job runner
    RequestClient persistentClient = new RequestClientBuilder().persistent().build();
    NullClientCallback cb = new NullClientCallback(persistentClient);
    InsertContext ctx = newInsertContextCurrent();

    TestableDefaultManifestPutter putter =
        new TestableDefaultManifestPutter(
            cb,
            new HashMap<>(),
            /*prio*/ (short) 0,
            FreenetURI.EMPTY_CHK_URI,
            /*defaultName*/ "index.html",
            ctx,
            /*persistent*/ true,
            /*forceKey*/ new byte[32], // force deterministic key path
            /*context*/ mock(ClientContext.class));

    ClientContext context = mock(ClientContext.class);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    Mockito.doNothing().when(jobRunner).queueNormalOrDrop(any());
    Mockito.when(context.getJobRunner(true)).thenReturn(jobRunner);

    // Act
    putter.innerOnResume(context);

    // Assert
    verify(context, times(1)).getJobRunner(true);
    verify(jobRunner, times(1)).queueNormalOrDrop(any());
  }

  // Reflection helper: extract the root container's metadata map
  @SuppressWarnings("unchecked")
  private static Map<String, Object> getRootContainerMetadataMap(BaseManifestPutter putter)
      throws Exception {
    Object rootContainerPH = readField(putter, "rootContainerPutHandler");
    assertNotNull(rootContainerPH, "root container handler present");
    Object origSFI = readField(rootContainerPH, "origSFI");
    Object origMetadata = readField(origSFI, "origMetadata");
    return (Map<String, Object>) origMetadata;
  }

  private static Object readField(Object target, String fieldName) throws Exception {
    Class<?> cls = target.getClass();
    while (cls != null) {
      try {
        Field f = cls.getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(target);
      } catch (NoSuchFieldException _) {
        cls = cls.getSuperclass();
      }
    }
    throw new NoSuchFieldException(fieldName);
  }
}

package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ContainerInserterTest {
  private static final String TEXT_PLAIN = "text/plain";
  private static final String FILENAME_A = "a.txt";

  private static final class InMemoryBucket implements RandomAccessBucket {
    private final String name;
    private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private boolean readOnly;
    private final AtomicInteger resumeCalls;

    InMemoryBucket(String name) {
      this(name, null);
    }

    InMemoryBucket(String name, AtomicInteger resumeCalls) {
      this.name = name;
      this.resumeCalls = resumeCalls;
    }

    // No direct raw byte access is needed in tests

    @Override
    public OutputStream getOutputStream() {
      if (readOnly) throw new IllegalStateException("Bucket is read-only");
      return baos;
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      return getOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(baos.toByteArray());
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public long size() {
      return baos.size();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public void setReadOnly() {
      readOnly = true;
    }

    @Override
    public void free() {
      baos.reset();
    }

    @Override
    public RandomAccessBucket createShadow() {
      return null; // not needed in tests
    }

    @Override
    public void onResume(ClientContext context) {
      if (resumeCalls != null) resumeCalls.incrementAndGet();
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      throw new UnsupportedOperationException("Not needed in tests");
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("Not needed in tests");
    }
  }

  private static final class FailingBucket implements RandomAccessBucket {
    @Override
    public OutputStream getOutputStream() throws IOException {
      throw new IOException("boom");
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      throw new IOException("boom");
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return "failing";
    }

    @Override
    public long size() {
      return 0;
    }

    @Override
    public boolean isReadOnly() {
      return false;
    }

    @Override
    public void setReadOnly() {
      // intentionally empty: read-only not relevant for this failing bucket stub
    }

    @Override
    public void free() {
      // intentionally empty: no resources to release in this stub
    }

    @Override
    public RandomAccessBucket createShadow() {
      return null;
    }

    @Override
    public void onResume(ClientContext context) {
      // intentionally empty: nothing to resume for this stub
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      // intentionally empty: persistence not needed in tests
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("Not needed in tests");
    }
  }

  private static final class TestPutter extends BaseClientPutter {
    private transient RequestClient rc;

    TestPutter(RequestClient rc) {
      super((short) 0, rc);
      this.rc = rc;
    }

    @Override
    public void onTransition(ClientPutState from, ClientPutState to, ClientContext context) {
      // intentionally empty: test-only putter does not forward transitions
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // intentionally empty: not used by tests
    }

    @Override
    public int getMinSuccessFetchBlocks() {
      return 0;
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    public FreenetURI getURI() {
      return null;
    }

    @Override
    public void cancel(ClientContext context) {
      // intentionally empty: not used by tests
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // no-op for tests
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return new ClientBaseCallback() {
        @Override
        public void onResume(ClientContext context) {
          // intentionally empty: callback resume not used in these tests
        }

        @Override
        public RequestClient getRequestClient() {
          return rc;
        }
      };
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // no-op for tests
    }

    @Override
    public boolean equals(Object obj) {
      // identity semantics are enough for test helper; delegate to super class
      return super.equals(obj);
    }

    @Override
    public int hashCode() {
      // delegate to super class to preserve identity-based semantics
      return super.hashCode();
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      rc = new RequestClientBuilder().persistent(false).build();
    }
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  @Mock private PutCompletionCallback callback;

  @Mock private ClientContext clientContext;

  @Test
  void cancel_whenCalled_invokesFailureOnceWithCancelledMode() {
    // Arrange
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);
    HashMap<String, Object> manifest = new HashMap<>();
    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            callback,
            manifest,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(true, false, ARCHIVE_TYPE.ZIP, null, (byte) 0, false),
            null);

    // Act
    inserter.cancel(clientContext);
    inserter.cancel(clientContext); // idempotent

    // Assert
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(callback, times(1))
        .onFailure(cap.capture(), Mockito.eq(inserter), Mockito.eq(clientContext));
    assertEquals(InsertException.InsertExceptionMode.CANCELLED, cap.getValue().mode);
  }

  @Test
  void accessors_whenConstructed_returnParentAndToken() {
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);
    Object token = new Object();
    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            callback,
            new HashMap<>(),
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(true, false, ARCHIVE_TYPE.ZIP, null, (byte) 0, false),
            token);

    assertEquals(parent, inserter.getParent());
    assertEquals(token, inserter.getToken());
  }

  @Test
  void resumeMetadata_whenUnknownType_throwsIllegalArgumentException() {
    Map<String, Object> map = new HashMap<>();
    map.put("bad", "unexpected");
    assertThrows(
        IllegalArgumentException.class, () -> ContainerInserter.resumeMetadata(map, clientContext));
  }

  @Test
  void resumeMetadata_whenNestedElements_invokesOnResumeForElementAndHandler() throws Exception {
    // Arrange: a ManifestElement with a bucket that counts onResume
    AtomicInteger bucketResume = new AtomicInteger();
    InMemoryBucket fileBucket = new InMemoryBucket("file", bucketResume);
    fileBucket.getOutputStream().write("data".getBytes(StandardCharsets.UTF_8));
    fileBucket.setReadOnly();
    ManifestElement me = new ManifestElement("file.txt", fileBucket, TEXT_PLAIN, 4);

    // Nested metadata (ignored by resumeMetadata)
    Metadata nested =
        new Metadata(
            DocumentType.SIMPLE_REDIRECT,
            null,
            null,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            new ClientMetadata(TEXT_PLAIN));

    // PutHandler mock should receive onResume
    BaseManifestPutter.PutHandler handler = Mockito.mock(BaseManifestPutter.PutHandler.class);

    Map<String, Object> map = new HashMap<>();
    Map<String, Object> sub = new HashMap<>();
    sub.put("m", nested);
    map.put("dir", sub);
    map.put("file.txt", me);
    map.put("handler", handler);

    // Act
    ContainerInserter.resumeMetadata(map, clientContext);

    // Assert
    assertEquals(1, bucketResume.get());
    verify(handler, times(1)).onResume(clientContext);
  }

  @Test
  void onResume_whenCalled_invokesCallbackAndResumesManifestElements() throws Exception {
    // Arrange
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);

    AtomicInteger bucketResume = new AtomicInteger();
    InMemoryBucket fileBucket = new InMemoryBucket("file", bucketResume);
    try (OutputStream os = fileBucket.getOutputStream()) {
      os.write("abc".getBytes(StandardCharsets.UTF_8));
    }
    fileBucket.setReadOnly();
    ManifestElement me = new ManifestElement("f.txt", fileBucket, TEXT_PLAIN, 3);
    HashMap<String, Object> manifest = new HashMap<>();
    manifest.put("f.txt", me);

    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            callback,
            manifest,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(true, false, ARCHIVE_TYPE.TAR, null, (byte) 0, false),
            null);

    // Act
    inserter.onResume(clientContext);

    // Assert: callback gets onResume, and the bucket got resumed via resumeMetadata()
    verify(callback, times(1)).onResume(clientContext);
    assertEquals(1, bucketResume.get());
  }

  @Test
  void createZipBucket_whenItemsPresent_writesEntriesAndReturnsMime() throws Exception {
    // Arrange: build a manifest with a single file and use an in-memory bucket factory
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);
    InMemoryBucket file = new InMemoryBucket("file");
    file.getOutputStream().write("hello".getBytes(StandardCharsets.UTF_8));
    file.setReadOnly();

    HashMap<String, Object> manifest = new HashMap<>();
    manifest.put(FILENAME_A, new ManifestElement(FILENAME_A, file, null, 5));

    when(clientContext.getBucketFactory(false))
        .thenReturn(_ -> new InMemoryBucket("bucket-" + java.util.UUID.randomUUID()));

    // Callback captures the SingleFileInserter to inspect the produced archive and aborts the flow
    PutCompletionCallback inspectingCb =
        new PutCompletionCallback() {
          @Override
          public void onSuccess(ClientPutState state, ClientContext context) {
            // intentionally empty: success not expected in this test
          }

          @Override
          public void onTransition(ClientPutState from, ClientPutState to, ClientContext ctx) {
            // Assert mime via block metadata
            SingleFileInserter sfi = (SingleFileInserter) to;
            ClientMetadata metadata =
                java.util.Objects.requireNonNull(
                    java.util.Objects.requireNonNull(sfi.block).clientMetadata);
            assertEquals("application/zip", metadata.getMIMEType());

            // Safely list entries without extracting to filesystem
            Set<String> names = new HashSet<>();
            try {
              java.nio.file.Path tmp = java.nio.file.Files.createTempFile("ziptest", ".zip");
              try {
                try (InputStream is = sfi.block.getData().getInputStream()) {
                  java.nio.file.Files.write(tmp, is.readAllBytes());
                }
                try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(tmp.toFile())) {
                  java.util.Enumeration<? extends java.util.zip.ZipEntry> e = zf.entries();
                  while (e.hasMoreElements()) {
                    java.util.zip.ZipEntry ze = e.nextElement();
                    String n = ze.getName();
                    // Basic zip-slip guards even though we don't extract
                    assertTrue(!n.startsWith("/") && !n.contains(".."));
                    names.add(n);
                  }
                }
              } finally {
                java.nio.file.Files.deleteIfExists(tmp);
              }
            } catch (IOException ioe) {
              throw new IllegalStateException(ioe);
            }

            assertTrue(names.contains(".metadata"));
            assertTrue(names.contains(FILENAME_A));

            // Abort further scheduling; the test expects this
            throw new IllegalStateException("stop-after-inspection");
          }

          @Override
          public void onFailure(InsertException e, ClientPutState state, ClientContext ctx) {
            throw new AssertionError("Unexpected failure: " + e, e);
          }

          @Override
          public void onFetchable(ClientPutState state) {
            // intentionally empty: not asserted in this test
          }

          @Override
          public void onEncode(
              network.crypta.keys.BaseClientKey usk, ClientPutState state, ClientContext context) {
            // intentionally empty: not expected in this test
          }

          @Override
          public void onMetadata(
              network.crypta.client.Metadata meta, ClientPutState state, ClientContext context) {
            // intentionally empty
          }

          @Override
          public void onMetadata(
              network.crypta.support.api.Bucket meta, ClientPutState state, ClientContext context) {
            // intentionally empty
          }

          @Override
          public void onBlockSetFinished(ClientPutState state, ClientContext context) {
            // intentionally empty: not relevant for this test
          }

          @Override
          public void onResume(ClientContext context) {
            // intentionally empty: resume callback not exercised in this test
          }
        };

    // Recreate inserter with our inspecting callback
    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            inspectingCb,
            manifest,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(false, false, ARCHIVE_TYPE.ZIP, null, (byte) 0, false),
            null);

    // Act: schedule and stop after inspection
    try {
      inserter.schedule(clientContext);
    } catch (RuntimeException expected) {
      assertEquals("stop-after-inspection", expected.getMessage());
    }
  }

  @Test
  void createTarBucket_whenItemsPresent_writesEntriesAndReturnsMime() throws Exception {
    // Arrange: manifest with a single file, in-memory bucket factory
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);

    InMemoryBucket fileBucket = new InMemoryBucket("in");
    try (OutputStream os = fileBucket.getOutputStream()) {
      os.write("hello".getBytes(StandardCharsets.UTF_8));
    }
    fileBucket.setReadOnly();

    HashMap<String, Object> manifest = new HashMap<>();
    manifest.put(FILENAME_A, new ManifestElement(FILENAME_A, fileBucket, null, 5));

    when(clientContext.getBucketFactory(false))
        .thenReturn(_ -> new InMemoryBucket("bucket-" + java.util.UUID.randomUUID()));

    PutCompletionCallback inspectingCb =
        new PutCompletionCallback() {
          @Override
          public void onSuccess(ClientPutState state, ClientContext context) {
            // intentionally empty: success not expected in this test
          }

          @Override
          public void onTransition(ClientPutState from, ClientPutState to, ClientContext ctx) {
            SingleFileInserter sfi = (SingleFileInserter) to;
            ClientMetadata metadata =
                java.util.Objects.requireNonNull(
                    java.util.Objects.requireNonNull(sfi.block).clientMetadata);
            assertEquals("application/x-tar", metadata.getMIMEType());

            Set<String> names = new HashSet<>();
            try (InputStream is = sfi.block.getData().getInputStream();
                TarArchiveInputStream tis = new TarArchiveInputStream(is)) {
              TarArchiveEntry te;
              while ((te = tis.getNextEntry()) != null) {
                if (!te.isDirectory()) names.add(te.getName());
              }
            } catch (IOException ioe) {
              throw new IllegalStateException(ioe);
            }

            assertTrue(names.contains(FILENAME_A));
            throw new IllegalStateException("stop-after-inspection");
          }

          @Override
          public void onFailure(InsertException e, ClientPutState state, ClientContext ctx) {
            throw new AssertionError("Unexpected failure: " + e, e);
          }

          @Override
          public void onFetchable(ClientPutState state) {
            // intentionally empty: not asserted in this test
          }

          @Override
          public void onEncode(
              network.crypta.keys.BaseClientKey usk, ClientPutState state, ClientContext context) {
            // intentionally empty: not expected in this test
          }

          @Override
          public void onMetadata(
              network.crypta.client.Metadata meta, ClientPutState state, ClientContext context) {
            // intentionally empty
          }

          @Override
          public void onMetadata(
              network.crypta.support.api.Bucket meta, ClientPutState state, ClientContext context) {
            // intentionally empty
          }

          @Override
          public void onBlockSetFinished(ClientPutState state, ClientContext context) {
            // intentionally empty: not relevant for this test
          }

          @Override
          public void onResume(ClientContext context) {
            // intentionally empty: resume callback not exercised in this test
          }
        };

    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            inspectingCb,
            manifest,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(false, false, ARCHIVE_TYPE.TAR, null, (byte) 0, false),
            null);

    try {
      inserter.schedule(clientContext);
    } catch (RuntimeException expected) {
      assertEquals("stop-after-inspection", expected.getMessage());
    }
  }

  @Test
  void schedule_whenOutputBucketThrows_reportsBucketErrorAndNoTransition() throws Exception {
    // Arrange
    RequestClient rc = new RequestClientBuilder().persistent(false).build();
    BaseClientPutter parent = new TestPutter(rc);
    HashMap<String, Object> manifest = new HashMap<>();
    // Include at least one file entry, so makeManifest will add it; irrelevant here
    InMemoryBucket fileBucket = new InMemoryBucket("in");
    fileBucket.getOutputStream().write(new byte[] {1});
    fileBucket.setReadOnly();
    manifest.put("a.bin", new ManifestElement("a.bin", fileBucket, null, 1));

    BucketFactory failing = _ -> new FailingBucket();
    when(clientContext.getBucketFactory(false)).thenReturn(failing);

    ContainerInserter inserter =
        new ContainerInserter(
            parent,
            callback,
            manifest,
            new FreenetURI("CHK", null, (byte[]) null, null, null),
            newInsertContext(),
            new InsertExecutionOptions(false, false, ARCHIVE_TYPE.ZIP, null, (byte) 0, false),
            null);

    // Act
    inserter.schedule(clientContext);

    // Assert: failure callback and no transition
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(callback, times(1))
        .onFailure(cap.capture(), Mockito.eq(inserter), Mockito.eq(clientContext));
    assertEquals(InsertException.InsertExceptionMode.INTERNAL_ERROR, cap.getValue().mode);
    verify(callback, never()).onTransition(any(), any(), any());
  }
}

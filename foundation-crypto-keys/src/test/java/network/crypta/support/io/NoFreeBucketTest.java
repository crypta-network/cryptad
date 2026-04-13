package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ResumeContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link NoFreeBucket}.
 *
 * <p>Tests follow AAA style and focus on delegation behavior, persistence header ordering, and
 * error propagation. External I/O is mocked where practical.
 */
class NoFreeBucketTest {

  // ----------------------------
  // Delegation: OutputStreams
  // ----------------------------

  static Stream<Arguments> outputStreamModes() {
    return Stream.of(Arguments.of(false), Arguments.of(true));
  }

  @ParameterizedTest
  @MethodSource("outputStreamModes")
  @DisplayName("getOutputStream[_Unbuffered] delegates and returns same instance")
  void getOutputStream_whenDelegating_returnsProxyStream(boolean unbuffered) throws IOException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      OutputStream expected = mock(OutputStream.class);
      if (unbuffered) when(proxy.getOutputStreamUnbuffered()).thenReturn(expected);
      else when(proxy.getOutputStream()).thenReturn(expected);

      // Act
      OutputStream actual =
          unbuffered ? bucket.getOutputStreamUnbuffered() : bucket.getOutputStream();

      // Assert
      assertSame(expected, actual, "Wrapper must return the proxy stream");
      if (unbuffered) verify(proxy, org.mockito.Mockito.times(1)).getOutputStreamUnbuffered();
      else verify(proxy, org.mockito.Mockito.times(1)).getOutputStream();
      verifyNoMoreInteractions(proxy);
    }
  }

  @ParameterizedTest
  @MethodSource("outputStreamModes")
  @DisplayName("getOutputStream[_Unbuffered] propagates IOException from proxy")
  void getOutputStream_whenProxyThrows_propagates(boolean unbuffered) throws IOException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      IOException boom = new IOException("boom");
      if (unbuffered) when(proxy.getOutputStreamUnbuffered()).thenThrow(boom);
      else when(proxy.getOutputStream()).thenThrow(boom);

      // Act + Assert (prepare a single-invocation Executable to satisfy static analysis)
      Executable exec = unbuffered ? bucket::getOutputStreamUnbuffered : bucket::getOutputStream;
      IOException thrown = assertThrows(IOException.class, exec);
      assertSame(boom, thrown);
    }
  }

  // ----------------------------
  // Delegation: InputStreams
  // ----------------------------

  static Stream<Arguments> inputStreamModes() {
    return Stream.of(Arguments.of(false), Arguments.of(true));
  }

  @ParameterizedTest
  @MethodSource("inputStreamModes")
  @DisplayName("getInputStream[_Unbuffered] delegates and returns same instance (including null)")
  void getInputStream_whenDelegating_returnsProxyStreamOrNull(boolean unbuffered)
      throws IOException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      InputStream expected = mock(InputStream.class);
      if (unbuffered) when(proxy.getInputStreamUnbuffered()).thenReturn(expected);
      else when(proxy.getInputStream()).thenReturn(expected);

      // Act
      InputStream actual = unbuffered ? bucket.getInputStreamUnbuffered() : bucket.getInputStream();

      // Assert
      assertSame(expected, actual, "Wrapper must return the proxy stream");
      if (unbuffered) verify(proxy, org.mockito.Mockito.times(1)).getInputStreamUnbuffered();
      else verify(proxy, org.mockito.Mockito.times(1)).getInputStream();
      verifyNoMoreInteractions(proxy);
    }
  }

  @ParameterizedTest
  @MethodSource("inputStreamModes")
  @DisplayName("getInputStream[_Unbuffered] returns null when proxy returns null")
  void getInputStream_whenProxyReturnsNull_returnsNull(boolean unbuffered) throws IOException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      if (unbuffered) when(proxy.getInputStreamUnbuffered()).thenReturn(null);
      else when(proxy.getInputStream()).thenReturn(null);

      // Act
      InputStream actual = unbuffered ? bucket.getInputStreamUnbuffered() : bucket.getInputStream();

      // Assert
      assertNull(actual, "Wrapper must pass through null InputStream");
    }
  }

  // ----------------------------
  // Delegation: simple value methods
  // ----------------------------

  @Test
  void getName_whenDelegating_returnsProxyValue() {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    when(proxy.getName()).thenReturn("proxy-name");
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act
      String name = bucket.getName();

      // Assert
      assertEquals("proxy-name", name);
      verify(proxy).getName();
      verifyNoMoreInteractions(proxy);
    }
  }

  static Stream<Long> sizeSamples() {
    return Stream.of(0L, 1L, 42L, Long.MAX_VALUE);
  }

  @ParameterizedTest
  @MethodSource("sizeSamples")
  void size_whenDelegating_returnsProxyValue(long value) {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    when(proxy.size()).thenReturn(value);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act + Assert
      assertEquals(value, bucket.size());
      verify(proxy).size();
      verifyNoMoreInteractions(proxy);
    }
  }

  @Test
  void readOnlyMethods_whenDelegating_behaveLikeProxy() {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    when(proxy.isReadOnly()).thenReturn(true);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act
      boolean ro = bucket.isReadOnly();
      bucket.setReadOnly();

      // Assert
      assertTrue(ro);
      verify(proxy).isReadOnly();
      verify(proxy).setReadOnly();
      verifyNoMoreInteractions(proxy);
    }
  }

  @Test
  void createShadow_whenDelegating_returnsProxyValue() {
    // Arrange
    Bucket shadow = mock(Bucket.class);
    Bucket proxy = mock(Bucket.class);
    when(proxy.createShadow()).thenReturn(shadow);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act
      Bucket result = bucket.createShadow();

      // Assert
      assertSame(shadow, result);
      verify(proxy).createShadow();
      verifyNoMoreInteractions(proxy);
    }
  }

  @Test
  void onResume_whenProxyThrows_propagates() throws ResumeFailedException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    ResumeContext ctx = mock(ResumeContext.class);
    ResumeFailedException boom = new ResumeFailedException("resume failed");
    doThrow(boom).when(proxy).onResume(ctx);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act + Assert
      ResumeFailedException thrown =
          assertThrows(ResumeFailedException.class, () -> bucket.onResume(ctx));
      assertSame(boom, thrown);
    }
  }

  // ----------------------------
  // No-op free()
  // ----------------------------

  @ParameterizedTest
  @MethodSource("times")
  void free_whenCalled_neverDelegatesToProxy(int calls) {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      // Act
      for (int i = 0; i < calls; i++) bucket.free();

      // Assert
      verify(proxy, never()).free();
      verifyNoMoreInteractions(proxy);
    }
  }

  static Stream<Integer> times() {
    return Stream.of(1, 2, 3);
  }

  // ----------------------------
  // storeTo() ordering and restore
  // ----------------------------

  @Test
  void storeTo_whenCalled_writesMagicThenDelegates() throws IOException {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy)) {
      final int sentinel = 0xDEADBEEF;
      doAnswer(
              invocation -> {
                DataOutputStream dos = invocation.getArgument(0);
                dos.writeInt(sentinel);
                return null;
              })
          .when(proxy)
          .storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));

      byte[] data;
      // Act
      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DataOutputStream dos = new DataOutputStream(baos)) {
        bucket.storeTo(dos);
        dos.flush();
        data = baos.toByteArray();
      }

      // Assert
      try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
        assertEquals(NoFreeBucket.MAGIC, dis.readInt(), "First int must be NoFreeBucket.MAGIC");
        assertEquals(sentinel, dis.readInt(), "Proxy must write immediately after MAGIC");
      }
    }
  }

  @Test
  void restore_whenReadingStoredBytes_restoresWrappedBucket() throws Exception {
    // Arrange
    File anyPath = new File("build/tmp/no-free-bucket-restore.test");
    try (Bucket inner = new FileBucket(anyPath, false, false, false, false);
        NoFreeBucket bucket = new NoFreeBucket(inner)) {
      byte[] serialized;
      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DataOutputStream dos = new DataOutputStream(baos)) {
        bucket.storeTo(dos);
        dos.flush();
        serialized = baos.toByteArray();
      }

      // Act
      Bucket restored;
      try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized))) {
        // Mocks for parameters not needed by FileBucket path
        FilenameGenerator fg = mock(FilenameGenerator.class);
        PersistentFileTracker pft = mock(PersistentFileTracker.class);
        MasterSecret masterKey = mock(MasterSecret.class);
        restored = BucketTools.restoreFrom(dis, fg, pft, masterKey);
      }

      // Assert
      assertThat(restored, is(instanceOf(NoFreeBucket.class)));
      // Verify that the restored wrapper delegates getName() to the inner FileBucket we stored
      String expectedName = anyPath.getName();
      try (var _ = restored) {
        assertEquals(expectedName, restored.getName());
      }
    }
  }

  // ----------------------------
  // Java serialization compatibility (new + legacy)
  // ----------------------------

  @Test
  void serialization_roundTrip_newFormat_appendedObject() throws Exception {
    byte[] payload = "hello-crypta".getBytes(StandardCharsets.UTF_8);
    try (Bucket wrapped = new ArrayBucket(payload);
        NoFreeBucket noFree = new NoFreeBucket(wrapped)) {
      byte[] bytes;
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
          ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        oos.writeObject(noFree);
        oos.flush();
        bytes = bos.toByteArray();
      }

      NoFreeBucket restored;
      try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        restored = (NoFreeBucket) ois.readObject();
      }

      assertEquals(payload.length, restored.size());
      try (InputStream ins = restored.getInputStream()) {
        assertArrayEquals(payload, ins.readAllBytes());
      }
      restored.free();
    }
  }

  @Test
  void serialization_whenProxyIsNotSerializable_throwsNotSerializableException() {
    // Arrange
    Bucket proxy = mock(Bucket.class);
    try (NoFreeBucket bucket = new NoFreeBucket(proxy);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      // Act + Assert
      NotSerializableException thrown =
          assertThrows(NotSerializableException.class, () -> oos.writeObject(bucket));
      assertEquals(proxy.getClass().getName(), thrown.getMessage());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void serialization_whenProxyIsNull_throwsNotSerializableException() {
    // Arrange
    try (NoFreeBucket bucket = new NoFreeBucket();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      // Act + Assert
      NotSerializableException thrown =
          assertThrows(NotSerializableException.class, () -> oos.writeObject(bucket));
      assertEquals("NoFreeBucket proxy is null", thrown.getMessage());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void readObject_whenProxyFieldDefaultedAndAppendedBucketPresent_restoresDelegate()
      throws Exception {
    // Arrange
    byte[] payload = "legacy-appended".getBytes(StandardCharsets.UTF_8);
    try (Bucket legacyBucket = new ArrayBucket(payload)) {
      NoFreeBucket target = newNoFreeBucketForDeserialization();

      // Act
      invokeReadObject(target, new ControlledObjectInputStream(true, null, legacyBucket, false));

      // Assert
      assertEquals(payload.length, target.size());
      try (InputStream ins = target.getInputStream()) {
        assertArrayEquals(payload, ins.readAllBytes());
      }
    }
  }

  @Test
  @SuppressWarnings("resource")
  void readObject_whenProxyFieldPresentButNull_throwsStreamCorruptedException() throws Exception {
    // Arrange
    NoFreeBucket target = newNoFreeBucketForDeserialization();

    // Act + Assert
    StreamCorruptedException thrown =
        assertThrows(
            StreamCorruptedException.class,
            () ->
                invokeReadObject(
                    target, new ControlledObjectInputStream(false, null, null, false)));
    assertEquals("NoFreeBucket: missing delegate in serialized form", thrown.getMessage());
  }

  @Test
  @SuppressWarnings("resource")
  void readObject_whenProxyFieldDefaultedAndAppendedObjectMissing_throwsStreamCorruptedException()
      throws Exception {
    // Arrange
    NoFreeBucket target = newNoFreeBucketForDeserialization();

    // Act + Assert
    StreamCorruptedException thrown =
        assertThrows(
            StreamCorruptedException.class,
            () ->
                invokeReadObject(target, new ControlledObjectInputStream(true, null, null, true)));
    assertEquals("NoFreeBucket: unexpected EOF while reading delegate", thrown.getMessage());
  }

  @Test
  void serialization_legacy_defaultOnly_isAccepted() throws Exception {
    byte[] payload = "legacy-stream".getBytes(StandardCharsets.UTF_8);
    try (Bucket legacyBucket = new ArrayBucket(payload)) {

      // Create instance via no-arg constructor; will be populated by readObject(ObjectInputStream)
      var ctor = NoFreeBucket.class.getDeclaredConstructor();
      ctor.setAccessible(true);
      NoFreeBucket target = ctor.newInstance();

      // Access private readObject to drive deserialization using a fake legacy ObjectInputStream
      var method = NoFreeBucket.class.getDeclaredMethod("readObject", ObjectInputStream.class);
      method.setAccessible(true);

      ObjectInputStream fakeIn =
          new ObjectInputStream(new ByteArrayInputStream(new byte[0])) {
            @Override
            protected void readStreamHeader() {
              // no header in this synthetic stream
            }

            @Override
            public GetField readFields() {
              ObjectStreamClass osc = ObjectStreamClass.lookup(NoFreeBucket.class);
              return new GetField() {
                @Override
                public ObjectStreamClass getObjectStreamClass() {
                  return osc;
                }

                @Override
                public boolean defaulted(String name) {
                  return !"proxy".equals(name);
                }

                @Override
                public Object get(String name, Object val) {
                  return "proxy".equals(name) ? legacyBucket : val;
                }

                @Override
                public boolean get(String name, boolean val) {
                  return val;
                }

                @Override
                public byte get(String name, byte val) {
                  return val;
                }

                @Override
                public char get(String name, char val) {
                  return val;
                }

                @Override
                public short get(String name, short val) {
                  return val;
                }

                @Override
                public int get(String name, int val) {
                  return val;
                }

                @Override
                public long get(String name, long val) {
                  return val;
                }

                @Override
                public float get(String name, float val) {
                  return val;
                }

                @Override
                public double get(String name, double val) {
                  return val;
                }
              };
            }
          };

      method.invoke(target, fakeIn);
      assertEquals(payload.length, target.size());
      try (InputStream ins = target.getInputStream()) {
        assertArrayEquals(payload, ins.readAllBytes());
      }
    }
  }

  // ----------------------------
  // Defensive: protected no-arg constructor leaves proxy null
  // ----------------------------

  @Test
  void anyMethod_whenConstructedViaNoArgConstructor_throwsNullPointerException() {
    // Arrange + Act + Assert (use try-with-resources and a single-invocation Executable)
    try (NoFreeBucket broken = new NoFreeBucket()) {
      org.junit.jupiter.api.function.Executable exec = broken::getName;
      assertThrows(NullPointerException.class, exec);
    }
  }

  private static NoFreeBucket newNoFreeBucketForDeserialization() throws Exception {
    var ctor = NoFreeBucket.class.getDeclaredConstructor();
    ctor.setAccessible(true);
    return ctor.newInstance();
  }

  private static void invokeReadObject(NoFreeBucket target, ObjectInputStream input)
      throws Exception {
    var method = NoFreeBucket.class.getDeclaredMethod("readObject", ObjectInputStream.class);
    method.setAccessible(true);
    try {
      method.invoke(target, input);
    } catch (java.lang.reflect.InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception exception) {
        throw exception;
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw e;
    }
  }

  private static final class ControlledObjectInputStream extends ObjectInputStream {
    private final boolean proxyDefaulted;
    private final Bucket proxyFieldValue;
    private final Object appendedObject;
    private final boolean appendedObjectMissing;

    ControlledObjectInputStream(
        boolean proxyDefaulted,
        Bucket proxyFieldValue,
        Object appendedObject,
        boolean appendedObjectMissing)
        throws IOException {
      super();
      this.proxyDefaulted = proxyDefaulted;
      this.proxyFieldValue = proxyFieldValue;
      this.appendedObject = appendedObject;
      this.appendedObjectMissing = appendedObjectMissing;
    }

    @Override
    public GetField readFields() {
      ObjectStreamClass osc = ObjectStreamClass.lookup(NoFreeBucket.class);
      return new GetField() {
        @Override
        public ObjectStreamClass getObjectStreamClass() {
          return osc;
        }

        @Override
        public boolean defaulted(String name) {
          return proxyDefaulted || !"proxy".equals(name);
        }

        @Override
        public Object get(String name, Object val) {
          return "proxy".equals(name) ? proxyFieldValue : val;
        }

        @Override
        public boolean get(String name, boolean val) {
          return val;
        }

        @Override
        public byte get(String name, byte val) {
          return val;
        }

        @Override
        public char get(String name, char val) {
          return val;
        }

        @Override
        public short get(String name, short val) {
          return val;
        }

        @Override
        public int get(String name, int val) {
          return val;
        }

        @Override
        public long get(String name, long val) {
          return val;
        }

        @Override
        public float get(String name, float val) {
          return val;
        }

        @Override
        public double get(String name, double val) {
          return val;
        }
      };
    }

    @Override
    protected Object readObjectOverride() throws IOException {
      if (appendedObjectMissing) {
        throw new EOFException();
      }
      return appendedObject;
    }
  }
}

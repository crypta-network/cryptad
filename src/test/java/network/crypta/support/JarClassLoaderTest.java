package network.crypta.support;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.ServiceLoader;
import java.util.function.Consumer;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static java.io.File.createTempFile;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.newOutputStream;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link JarClassLoader}. */
@SuppressWarnings("java:S100") // Test method names use when/then style for clarity
class JarClassLoaderTest {

  @TempDir Path tmp;

  private Path classesDir;

  @BeforeEach
  void setup() throws IOException {
    classesDir = Files.createDirectories(tmp.resolve("classes"));
  }

  // Existing tests rewritten to follow naming guideline (AAA inside)
  @Test
  void serviceLoader_whenJarHasServiceFile_findsImplementation() throws Exception {
    // Arrange
    JarClassLoader classLoader = new JarClassLoader(createJarFileWithServiceLoaderEntry());

    // Act
    ServiceLoader<TestInterface> testInterface =
        ServiceLoader.load(TestInterface.class, classLoader);
    List<TestInterface> implementations = new ArrayList<>();
    testInterface.iterator().forEachRemaining(implementations::add);

    // Assert
    assertThat(implementations, containsInAnyOrder(instanceOf(TestImplementation.class)));
  }

  @Test
  void getResource_whenDirectoryEntry_exists_returnsSingleUrl() throws Exception {
    // Arrange
    try (JarClassLoader classLoader = new JarClassLoader(createJarFileWithDirectoryEntries())) {
      // Act
      URL url = classLoader.getResource("META-INF/freenet-jar-class-loader-test");

      // Assert
      assertThat(url, notNullValue());
    }
  }

  @Test
  void getResources_whenDirectoryEntry_exists_enumeratesUrl() throws Exception {
    // Arrange
    try (JarClassLoader classLoader = new JarClassLoader(createJarFileWithDirectoryEntries())) {
      // Act
      Enumeration<URL> urls = classLoader.getResources("META-INF/freenet-jar-class-loader-test");

      // Assert
      assertThat(urls.nextElement().toString(), containsString("jar-class-loader-test-"));
    }
  }

  // New comprehensive tests

  @Test
  void loadClass_whenClassPresentInJar_loadsAndDefinesPackageAttributes() throws Exception {
    // Arrange: compile a tiny class and jar it with manifest attributes
    String pkg = "testpkg.jarcl";
    String cls = "Greeter";
    String fqn = pkg + "." + cls;
    compileJavaClass(
        pkg,
        cls,
        "package "
            + pkg
            + "; public class "
            + cls
            + " { public String greet(){ return \"hi\"; } }");

    Manifest m = new Manifest();
    Attributes main = m.getMainAttributes();
    main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
    main.put(Attributes.Name.SPECIFICATION_TITLE, "SpecTitle");
    main.put(Attributes.Name.SPECIFICATION_VERSION, "1.2.3");
    main.put(Attributes.Name.SPECIFICATION_VENDOR, "SpecVendor");
    main.put(Attributes.Name.IMPLEMENTATION_TITLE, "ImplTitle");
    main.put(Attributes.Name.IMPLEMENTATION_VERSION, "9.8.7");
    main.put(Attributes.Name.IMPLEMENTATION_VENDOR, "ImplVendor");

    File jar = createJarWith(m, jarOut -> addCompiledClass(jarOut, pkg, cls));

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act
      Class<?> c = cl.loadClass(fqn);

      // Assert: class loads and package attributes are set from manifest
      assertEquals(fqn, c.getName());
      Package p = c.getPackage();
      assertNotNull(p);
      assertEquals("SpecTitle", p.getSpecificationTitle());
      assertEquals("1.2.3", p.getSpecificationVersion());
      assertEquals("SpecVendor", p.getSpecificationVendor());
      assertEquals("ImplTitle", p.getImplementationTitle());
      assertEquals("9.8.7", p.getImplementationVersion());
      assertEquals("ImplVendor", p.getImplementationVendor());
    }
  }

  @Test
  void loadClass_whenClassMissing_throwsClassNotFoundException() throws Exception {
    // Arrange
    File jar = createEmptyJar();

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act + Assert
      assertThrows(ClassNotFoundException.class, () -> cl.loadClass("com.example.DoesNotExist"));
    }
  }

  @Test
  void getResourceAsStream_whenResourceInJar_returnsStreamWithContent() throws Exception {
    // Arrange
    byte[] payload = "hello-from-jar".getBytes(UTF_8);
    File jar =
        createJarWith(
            null,
            jarOut -> {
              addDirectory(jarOut, "res/");
              addBytes(jarOut, "res/data.txt", payload);
            });

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act
      try (InputStream is = cl.getResourceAsStream("res/data.txt")) {
        // Assert
        assertNotNull(is);
        assertArrayEquals(payload, readAllBytes(is));
      }
    }
  }

  @Test
  void getResourceAsStream_whenNameHasLeadingSlash_stripsAndFinds() throws Exception {
    // Arrange
    byte[] payload = "hello-leading-slash".getBytes(UTF_8);
    File jar =
        createJarWith(
            null,
            jarOut -> {
              addDirectory(jarOut, "assets/");
              addBytes(jarOut, "assets/data.txt", payload);
            });

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act
      try (InputStream is = cl.getResourceAsStream("/assets/data.txt")) {
        // Assert
        assertNotNull(is);
        assertArrayEquals(payload, readAllBytes(is));
      }
    }
  }

  @Test
  void serviceLoader_whenJarHasOtherServiceFile_findsOtherImplementation() throws Exception {
    // Arrange
    JarClassLoader classLoader =
        new JarClassLoader(createJarFileWithServiceLoaderEntry(AnotherImplementation.class));

    // Act
    ServiceLoader<TestInterface> testInterface =
        ServiceLoader.load(TestInterface.class, classLoader);
    List<TestInterface> implementations = new ArrayList<>();
    testInterface.iterator().forEachRemaining(implementations::add);

    // Assert
    assertThat(implementations, containsInAnyOrder(instanceOf(AnotherImplementation.class)));
  }

  @Test
  void getResourceAsStream_whenResourceInParent_delegatesToParent() throws Exception {
    // Arrange: pick a resource known to be on the test classpath (this test class)
    String testResource = this.getClass().getName().replace('.', '/') + ".class";
    File jar = createEmptyJar();

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act
      try (InputStream is = cl.getResourceAsStream(testResource)) {
        // Assert
        assertNotNull(is);
        byte[] firstBytes = new byte[4];
        int n = is.read(firstBytes);
        assertTrue(n > 0);
      }
    }
  }

  @Test
  void findResource_whenNoSuchEntry_returnsNull() throws Exception {
    // Arrange
    File jar = createEmptyJar();

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act + Assert
      assertNull(cl.findResource("does/not/exist.txt"));
    }
  }

  @Test
  void getResources_whenFileEntryExists_returnsThatUrl() throws Exception {
    // Arrange
    File jar = createJarWith(null, jarOut -> addBytes(jarOut, "a/file.txt", "x".getBytes(UTF_8)));

    try (JarClassLoader cl = new JarClassLoader(jar)) {
      // Act
      Enumeration<URL> urls = cl.getResources("a/file.txt");

      // Assert
      assertTrue(urls.hasMoreElements());
      assertThat(urls.nextElement().toString(), containsString("!/a/file.txt"));
    }
  }

  @Test
  void constructor_withUrlAndWrongLength_throwsIOException() throws Exception {
    // Arrange: create a tiny jar and pass an incorrect length to force EOF
    File jar = createEmptyJar();
    URL url = jar.toURI().toURL();
    long wrongLength = jar.length() + 1; // longer than actual

    // Act + Assert (use try-with-resources inside lambda to satisfy resource checkers)
    assertThrows(
        IOException.class,
        () -> {
          try (JarClassLoader ignored = new JarClassLoader(url, wrongLength)) {
            // Keep the resource in scope so the block is not empty for static analyzers.
            assertNotNull(ignored);
          }
        });
  }

  @Test
  void constructor_withUrlAndUnknownLength_readsToEof() throws Exception {
    // Arrange
    File jar = createEmptyJar();
    URL url = jar.toURI().toURL();

    // Act + Assert: should not throw
    try (JarClassLoader cl = new JarClassLoader(url, -1)) {
      assertNotNull(cl);
    }
  }

  @Test
  void close_whenClosed_thenSubsequentAccessThrowsIllegalState() throws Exception {
    // Arrange
    File jar = createJarWith(null, jarOut -> addBytes(jarOut, "res/x.txt", new byte[] {1, 2, 3}));
    JarClassLoader cl = new JarClassLoader(jar);

    // Act
    cl.close();

    // Assert: most JarFile operations throw IllegalStateException once closed
    assertThrows(IllegalStateException.class, () -> cl.findResource("res/x.txt"));
  }

  // -------------------- helpers --------------------

  /**
   * Creates a temporary JAR file that contains a file that will be used by {@link ServiceLoader} in
   * order to provide an implementation of {@link TestInterface}.
   */
  private File createJarFileWithServiceLoaderEntry() throws Exception {
    return createJarFileWithServiceLoaderEntry(TestImplementation.class);
  }

  private File createJarFileWithServiceLoaderEntry(Class<? extends TestInterface> implClass)
      throws Exception {
    return createJarFile(jarFileStream -> createServiceLoaderEntryFor(implClass, jarFileStream));
  }

  /** Creates a JAR with the META-INF directory and a test subdirectory entry. */
  private File createJarFileWithDirectoryEntries() throws IOException {
    return createJarFile(
        jarFileStream -> {
          jarFileStream.putNextEntry(new ZipEntry("META-INF/"));
          jarFileStream.putNextEntry(new ZipEntry("META-INF/freenet-jar-class-loader-test/"));
        });
  }

  private File createJarFile(ThrowingConsumer<ZipOutputStream, IOException> outputStreamConsumer)
      throws IOException {
    File temporaryFile = createTempFile("jar-class-loader-test-", ".jar");
    temporaryFile.deleteOnExit();
    try (OutputStream fileOutputStream = newOutputStream(temporaryFile.toPath());
        JarOutputStream jarFileStream = new JarOutputStream(fileOutputStream)) {
      outputStreamConsumer.accept(jarFileStream);
    }
    return temporaryFile;
  }

  private File createEmptyJar() throws IOException {
    return createJarWith(null, jarOut -> {});
  }

  private File createJarWith(Manifest manifest, ThrowingConsumer<JarOutputStream, IOException> body)
      throws IOException {
    File temporaryFile = createTempFile("jar-class-loader-test-", ".jar");
    temporaryFile.deleteOnExit();
    try (OutputStream fos = newOutputStream(temporaryFile.toPath());
        JarOutputStream jos =
            manifest == null ? new JarOutputStream(fos) : new JarOutputStream(fos, manifest)) {
      body.accept(jos);
    }
    return temporaryFile;
  }

  private void addDirectory(JarOutputStream jos, String dir) throws IOException {
    if (!dir.endsWith("/")) dir = dir + "/";
    jos.putNextEntry(new JarEntry(dir));
  }

  private void addBytes(JarOutputStream jos, String name, byte[] content) throws IOException {
    jos.putNextEntry(new JarEntry(name));
    jos.write(content);
  }

  private void addCompiledClass(JarOutputStream jos, String pkg, String cls) throws IOException {
    Path classFile = classesDir.resolve(pkg.replace('.', '/')).resolve(cls + ".class");
    addBytes(jos, pkg.replace('.', '/') + "/" + cls + ".class", Files.readAllBytes(classFile));
  }

  private void compileJavaClass(String pkg, String cls, String src) throws IOException {
    Path srcDir = Files.createDirectories(tmp.resolve("src"));
    Path javaFile = srcDir.resolve(pkg.replace('.', '/')).resolve(cls + ".java");
    Path javaParent = javaFile.getParent();
    if (javaParent != null) {
      Files.createDirectories(javaParent);
    }
    Files.writeString(javaFile, src, UTF_8);
    int rc =
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, "-d", classesDir.toString(), javaFile.toString());
    if (rc != 0) {
      throw new IOException("javac failed for " + javaFile + ": rc=" + rc);
    }
  }

  private static byte[] readAllBytes(InputStream is) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    int r;
    while ((r = is.read(buf)) != -1) {
      bos.write(buf, 0, r);
    }
    return bos.toByteArray();
  }

  private static void createServiceLoaderEntryFor(
      Class<? extends TestInterface> implementationClass, ZipOutputStream zipOutputStream)
      throws IOException {
    ZipEntry serviceFileEntry = new ZipEntry("META-INF/services/" + TestInterface.class.getName());
    zipOutputStream.putNextEntry(serviceFileEntry);
    zipOutputStream.write((implementationClass.getName() + "\n").getBytes(UTF_8));
  }

  /**
   * {@link Consumer}-like interface that declares exceptions on the {@link #accept(Object)},
   * allowing lambdas that throw exceptions.
   *
   * @param <T> The type of object being consumed
   * @param <E> The type of the exception
   */
  private interface ThrowingConsumer<T, E extends Throwable> {
    void accept(T t) throws E;
  }

  /** Interface for use with the {@link ServiceLoader}. */
  public interface TestInterface {}

  /** Implementation of the {@link TestInterface} interface. */
  public static class TestImplementation implements TestInterface {}

  /** Another implementation for parameter variability in tests. */
  public static class AnotherImplementation implements TestInterface {}
}

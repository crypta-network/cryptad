package network.crypta.support;

import java.util.HashMap;
import network.crypta.support.api.ManifestElement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ContainerSizeEstimatorTest {

  private static ManifestElement file(String name, long size) {
    ManifestElement me = Mockito.mock(ManifestElement.class);
    Mockito.when(me.getSize()).thenReturn(size);
    Mockito.when(me.getName()).thenReturn(name);
    return me;
  }

  @ParameterizedTest
  @DisplayName("tarItemSize rounds up to 512-byte blocks plus header")
  @CsvSource({
    "-1,512",
    "0,512",
    "1,1024",
    "511,1024",
    "512,1024",
    "513,1536",
    "1024,1536",
    "1025,2048"
  })
  void tarItemSize_whenBoundary_expectRounded(long size, long expected) {
    long actual = ContainerSizeEstimator.tarItemSize(size);
    assertEquals(expected, actual);
  }

  @ParameterizedTest
  @DisplayName("getContainerItemSize defaults to TAR behavior")
  @CsvSource({"-5", "0", "1", "12345"})
  void getContainerItemSize_whenDefaultTar_expectEqual(long size) {
    long expected = ContainerSizeEstimator.tarItemSize(size);
    long actual = ContainerSizeEstimator.getContainerItemSize(size);
    assertEquals(expected, actual);
  }

  @Test
  @DisplayName("getSubTreeSize with only files: counts files, redirects and metadata overheads")
  void getSubTreeSize_whenOnlyFiles_expectCorrectSizes() {
    HashMap<String, Object> meta = new HashMap<>();
    // Sizes chosen around maxItemSize threshold.
    meta.put("small1", file("a", 0)); // +512 files, +512 + 2*(128+1) noLimit
    meta.put("small2", file("bc", 1)); // +1024 files, +1024 + 2*(128+2) noLimit
    meta.put("large", file("large", 101)); // redirect in files (+512), noLimit gets item + 1*meta
    meta.put("redir", file("r", -1)); // redirect: +512 both

    long maxItemSize = 100;
    long maxContainerSize = 1_000_000L;
    int maxDeep = 1;

    ContainerSizeEstimator.ContainerSize res =
        ContainerSizeEstimator.getSubTreeSize(meta, maxItemSize, maxContainerSize, maxDeep);

    long expectedFiles = 512 + 1024 + 512 + 512; // 2560
    long expectedFilesNoLimit =
        // small1
        (512 + 2 * (128 + 1))
            // small2
            + (1024 + 2 * (128 + 2))
            // large(>max): item + 1*meta
            + (1024 + (128 + 5))
            // redirect: fixed 512
            + 512; // 3723

    assertEquals(expectedFiles, res.getSizeFiles(), "files size");
    assertEquals(expectedFilesNoLimit, res.getSizeFilesNoLimit(), "files no-limit size");
    assertEquals(0L, res.getSizeSubTrees(), "subtrees size");
    assertEquals(0L, res.getSizeSubTreesNoLimit(), "subtrees no-limit size");
    assertEquals(expectedFiles, res.getSizeTotal(), "total size");
    assertEquals(expectedFilesNoLimit, res.getSizeTotalNoLimit(), "total no-limit size");
  }

  @Test
  @DisplayName("getSubTreeSize respects recursion depth for subdirectories")
  void getSubTreeSize_whenSubdirsAndDepth_expectRecursionCounts() {
    HashMap<String, Object> child = new HashMap<>();
    child.put("x", file("x", 0)); // child contributes 512 files, 512+2*(128+1)=770 noLimit

    HashMap<String, Object> meta = new HashMap<>();
    meta.put("dir", child); // subdir
    meta.put("top", file("top", 1)); // top-level small file

    long maxItemSize = 100;
    long maxContainerSize = 1_000_000L;
    int maxDeep = 1; // allow one level

    ContainerSizeEstimator.ContainerSize res =
        ContainerSizeEstimator.getSubTreeSize(meta, maxItemSize, maxContainerSize, maxDeep);

    long expectedTopFile = 1024; // tar(1)
    long expectedTopFileNoLimit = 1024 + 2 * (128 + 3); // name="top"

    long expectedSubTrees = 512 /*dir header*/ + 512 /*child total files*/; // 1024
    long expectedSubTreesNoLimit = 770; // child total no-limit

    assertEquals(expectedTopFile, res.getSizeFiles(), "files size");
    assertEquals(expectedTopFileNoLimit, res.getSizeFilesNoLimit(), "files no-limit size");
    assertEquals(expectedSubTrees, res.getSizeSubTrees(), "subtrees size");
    assertEquals(expectedSubTreesNoLimit, res.getSizeSubTreesNoLimit(), "subtrees no-limit size");
    assertEquals(expectedTopFile + expectedSubTrees, res.getSizeTotal(), "total size");
    assertEquals(
        expectedTopFileNoLimit + expectedSubTreesNoLimit,
        res.getSizeTotalNoLimit(),
        "total no-limit size");
  }

  @Test
  @DisplayName("getSubTreeSize with maxDeep=0 excludes subdirectories")
  void getSubTreeSize_whenMaxDeepZero_excludesSubdirs() {
    HashMap<String, Object> child = new HashMap<>();
    child.put("x", file("x", 0));

    HashMap<String, Object> meta = new HashMap<>();
    meta.put("dir", child);
    meta.put("top", file("top", 1));

    ContainerSizeEstimator.ContainerSize res =
        ContainerSizeEstimator.getSubTreeSize(meta, 100, 1_000_000L, 0);

    long expectedTopFile = 1024;
    long expectedTopFileNoLimit = 1024 + 2 * (128 + 3);

    assertEquals(expectedTopFile, res.getSizeFiles(), "files size");
    assertEquals(expectedTopFileNoLimit, res.getSizeFilesNoLimit(), "files no-limit size");
    assertEquals(0L, res.getSizeSubTrees(), "subtrees size");
    assertEquals(0L, res.getSizeSubTreesNoLimit(), "subtrees no-limit size");
  }

  @Test
  @DisplayName("getSubTreeSize breaks file loop when max container size exceeded")
  void getSubTreeSize_whenMaxContainerExceeded_breaksFilesLoop() {
    HashMap<String, Object> meta = new HashMap<>();
    // Four identical small files so order does not matter; each adds 512 to files size.
    meta.put("a", file("a", 0));
    meta.put("b", file("b", 0));
    meta.put("c", file("c", 0));
    meta.put("d", file("d", 0));

    long maxItemSize = 1000; // treat all as direct files
    long maxContainerSize = 1024; // break after third file (1536 > 1024)

    ContainerSizeEstimator.ContainerSize res =
        ContainerSizeEstimator.getSubTreeSize(meta, maxItemSize, maxContainerSize, 0);

    long expectedFiles = 512 * 3; // third pushes it over and triggers break
    long expectedFilesNoLimit = 3 * (512 + 2 * (128 + 1)); // names all length 1

    assertEquals(expectedFiles, res.getSizeFiles(), "files size");
    assertEquals(expectedFilesNoLimit, res.getSizeFilesNoLimit(), "files no-limit size");
    assertEquals(0L, res.getSizeSubTrees(), "subtrees size");
    assertEquals(0L, res.getSizeSubTreesNoLimit(), "subtrees no-limit size");
  }

  @Test
  @DisplayName("getSubTreeSize breaks subdir loop when max container size exceeded")
  void getSubTreeSize_whenMaxContainerExceeded_breaksSubdirLoop() {
    HashMap<String, Object> dir1 = new HashMap<>();
    dir1.put("x", file("x", 0)); // child total: files=512, noLimit=770

    HashMap<String, Object> dir2 = new HashMap<>();
    dir2.put("y", file("y", 0));

    HashMap<String, Object> meta = new HashMap<>();
    meta.put("dir1", dir1);
    meta.put("dir2", dir2);

    long maxItemSize = 100;
    long maxContainerSize = 800; // First dir -> 512(header)+512(child)=1024 > 800 => break

    ContainerSizeEstimator.ContainerSize res =
        ContainerSizeEstimator.getSubTreeSize(meta, maxItemSize, maxContainerSize, 1);

    assertEquals(1024L, res.getSizeSubTrees(), "subtrees size after first dir only");
    assertEquals(770L, res.getSizeSubTreesNoLimit(), "subtrees no-limit after first dir only");
  }

  @Test
  @DisplayName("getSubTreeSize with null metadata throws NPE")
  void getSubTreeSize_whenNullMetadata_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> ContainerSizeEstimator.getSubTreeSize(null, 100, 1000, 1));
  }
}

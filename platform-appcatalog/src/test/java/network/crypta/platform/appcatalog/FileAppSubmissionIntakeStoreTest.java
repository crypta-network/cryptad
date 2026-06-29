package network.crypta.platform.appcatalog;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class FileAppSubmissionIntakeStoreTest {
  @Test
  void submissionPackagePath_whenSubmissionIdIsDotSegment_expectRejected(@TempDir Path tempDir) {
    FileAppSubmissionIntakeStore store = new FileAppSubmissionIntakeStore(tempDir);

    for (String submissionId : List.of(".", "..")) {
      assertThrows(AppCatalogException.class, () -> store.submissionPackagePath(submissionId));
      assertThrows(
          AppCatalogException.class,
          () -> FileAppSubmissionIntakeStore.safeSubmissionIdComponent(submissionId));
    }
  }
}

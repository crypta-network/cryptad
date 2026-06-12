package network.crypta.platform.appcatalog;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogBuildRequestTest {
  private static final String CATALOG_NAME = "Development Apps";
  private static final Instant GENERATED_AT = Instant.parse("2026-04-29T12:34:56Z");

  @TempDir private Path tempDir;

  @Test
  void constructor_whenDescriptorFilesAreMutable_expectNormalizedImmutableSnapshot() {
    Path descriptorFile = tempDir.resolve("entry.properties");
    List<Path> descriptorFiles = new ArrayList<>(List.of(descriptorFile));

    AppCatalogBuildRequest request =
        new AppCatalogBuildRequest(
            " Dev-Catalog ", " " + CATALOG_NAME + " ", GENERATED_AT, descriptorFiles);
    descriptorFiles.set(0, tempDir.resolve("other.properties"));

    assertEquals("dev-catalog", request.catalogId());
    assertEquals(CATALOG_NAME, request.catalogName());
    assertEquals(
        List.of(descriptorFile.toAbsolutePath().normalize()), request.entryDescriptorFiles());
    Iterator<Path> descriptorIterator = request.entryDescriptorFiles().iterator();
    assertEquals(descriptorFile.toAbsolutePath().normalize(), descriptorIterator.next());
    assertThrows(UnsupportedOperationException.class, descriptorIterator::remove);
  }

  @Test
  void withOutputFile_whenRelativePathProvided_expectNormalizedOutputPath() {
    Path descriptorFile = tempDir.resolve("entry.properties");
    Path outputFile = Path.of("catalog").resolve("..").resolve("cryptad-app-catalog.properties");
    AppCatalogBuildRequest request =
        new AppCatalogBuildRequest("dev", CATALOG_NAME, GENERATED_AT, List.of(descriptorFile));

    AppCatalogBuildRequest withOutput = request.withOutputFile(outputFile);

    assertEquals(outputFile.toAbsolutePath().normalize(), withOutput.outputFile().orElseThrow());
    assertEquals(request.entryDescriptorFiles(), withOutput.entryDescriptorFiles());
  }

  @Test
  void withOutputFile_whenReviewReceiptFilesArePresent_expectPreservedNormalizedReceipts() {
    Path descriptorFile = tempDir.resolve("entry.properties");
    Path receiptFile = Path.of("receipts").resolve("..").resolve("review-receipt.properties");
    Path outputFile = tempDir.resolve("cryptad-app-catalog.properties");
    AppCatalogBuildRequest request =
        new AppCatalogBuildRequest(
            "dev", CATALOG_NAME, GENERATED_AT, List.of(descriptorFile), List.of(receiptFile));

    AppCatalogBuildRequest withOutput = request.withOutputFile(outputFile);

    assertEquals(List.of(receiptFile.toAbsolutePath().normalize()), request.reviewReceiptFiles());
    assertEquals(request.reviewReceiptFiles(), withOutput.reviewReceiptFiles());
    assertEquals(outputFile.toAbsolutePath().normalize(), withOutput.outputFile().orElseThrow());
  }

  @Test
  void constructor_whenLiteralNullOutputFileProvided_expectInMemoryRequest() {
    Path descriptorFile = tempDir.resolve("entry.properties");

    AppCatalogBuildRequest request =
        new AppCatalogBuildRequest(
            "dev", CATALOG_NAME, GENERATED_AT, List.of(descriptorFile), List.of(), null);

    assertTrue(request.outputFile().isEmpty());
    assertEquals(AppCatalogSecurityPolicy.EMPTY, request.securityPolicy());
  }

  @Test
  void constructor_whenSecurityPolicyAndNullOutputFileProvided_expectPolicyPreserved() {
    Path descriptorFile = tempDir.resolve("entry.properties");

    AppCatalogBuildRequest request =
        new AppCatalogBuildRequest(
            "dev",
            CATALOG_NAME,
            GENERATED_AT,
            List.of(descriptorFile),
            List.of(),
            AppCatalogSecurityPolicy.EMPTY,
            null);

    assertTrue(request.outputFile().isEmpty());
    assertEquals(AppCatalogSecurityPolicy.EMPTY, request.securityPolicy());
  }

  @Test
  void constructor_whenDescriptorFilesAreEmpty_expectInvalidCatalogEntry() {
    List<Path> emptyDescriptorFiles = List.of();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppCatalogBuildRequest(
                    "dev", CATALOG_NAME, GENERATED_AT, emptyDescriptorFiles));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }
}

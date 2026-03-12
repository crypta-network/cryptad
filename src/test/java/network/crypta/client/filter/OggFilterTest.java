package network.crypta.client.filter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static network.crypta.client.filter.ResourceFileUtil.resourceToDataInputStream;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OggFilterTest {
  private OggFilter filter;

  @Mock private FilterCallback callback;

  @BeforeEach
  void setUp() {
    filter = new OggFilter();
  }

  @Test
  void readFilter_whenInvalidHeader_expectDataFilterExceptionAndNoOutput() throws IOException {
    try (DataInputStream input = resourceToDataInputStream("./ogg/invalid_header.ogg")) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(input, new ByteArrayOutputStream(), null, null, null, callback));
      verifyNoInteractions(callback);
    }
  }

  @Test
  void readFilter_whenContainsSubpages_expectDataFilterExceptionAndNoOutput() throws IOException {
    try (DataInputStream input = resourceToDataInputStream("./ogg/contains_subpages.ogg");
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(input, output, null, null, null, callback));
      assertArrayEquals(new byte[] {}, output.toByteArray());
      verifyNoInteractions(callback);
    }
  }

  /**
   * The purpose of this test is to create the test output file so you can check it with a video
   * player when the reference file is available in the test resources.
   */
  @Test
  void readFilter_whenValidVideoSegment_expectExactExpectedOutput() throws IOException {
    ByteArrayOutputStream expectedData = new ByteArrayOutputStream();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (DataInputStream input =
        resourceToDataInputStream(
            "./ogg/36C3_-_opening--cc-by--c3voc--fem-ags-opensuse--ccc--filtered.ogv")) {
      input.transferTo(expectedData);
    }
    try (DataInputStream input =
        resourceToDataInputStream(
            "./ogg/36C3_-_opening--cc-by--c3voc--fem-ags-opensuse--ccc--orig.ogv")) {
      filter.readFilter(input, output, null, null, null, callback);
      writeToTestOutputFile(output);
    }
    assertArrayEquals(expectedData.toByteArray(), output.toByteArray());
    verifyNoInteractions(callback);
  }

  @Test
  void readFilter_whenNonsensicalInterruption_expectDataFilterExceptionAndNoOutput()
      throws IOException {
    try (DataInputStream input = resourceToDataInputStream("./ogg/nonsensical_interruption.ogg");
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(input, output, null, null, null, callback));
      assertArrayEquals(new byte[] {}, output.toByteArray());
      verifyNoInteractions(callback);
    }
  }

  @Test
  void readFilter_whenPagesOutOfOrder_expectDataFilterException() throws IOException {
    try (DataInputStream input = resourceToDataInputStream("./ogg/pages_out_of_order.ogg")) {
      assertThrows(
          DataFilterException.class,
          () -> filter.readFilter(input, new ByteArrayOutputStream(), null, null, null, callback));
      verifyNoInteractions(callback);
    }
  }

  private void writeToTestOutputFile(ByteArrayOutputStream output) throws IOException {
    URL resource =
        getClass()
            .getResource(
                "./ogg/36C3_-_opening--cc-by--c3voc--fem-ags-opensuse--ccc--filtered-testoutput.ogv");
    if (resource == null) {
      return; // Skip writing when the reference file is unavailable
    }
    String testOutputFile = resource.getFile();
    try (FileOutputStream newFileStream = new FileOutputStream(testOutputFile)) {
      output.writeTo(newFileStream);
    }
  }
}

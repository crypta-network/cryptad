package network.crypta.platform.api.queue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class QueueApiHandlerTest {
  @Test
  void snapshot_whenRequested_expectDetachedHtmlWithoutLegacyRuntimePlaceholders() {
    RecordingQueuePagePort queuePagePort = new RecordingQueuePagePort();
    queuePagePort.pageSnapshot =
        new QueuePageSnapshot(
            "Downloads",
            "<div>before<!--CRYPTA_ALERT_SUMMARY--><!--CRYPTA_QUEUE_FORM_PASSWORD-->"
                + "<!--CRYPTA_QUEUE_PANIC_BOX-->after</div>");
    RecordingQueueCompletionPort queueCompletionPort = new RecordingQueueCompletionPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            queuePagePort,
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            queueCompletionPort);

    Map<String, Object> snapshot =
        handler.snapshot(
            orderedParameters(
                Map.entry("page", List.of("downloads")),
                Map.entry("advancedMode", List.of("true")),
                Map.entry("sortBy", List.of("priority")),
                Map.entry("reversed", List.of("true"))));

    assertEquals(
        new QueuePageRequest(false, true, "priority", true), queuePagePort.lastPageRequest);
    assertEquals(List.of(false), queueCompletionPort.startedSides);
    assertEquals("downloads", snapshot.get("page"));
    assertEquals("Downloads", snapshot.get("pageTitle"));
    assertEquals("<div>beforeafter</div>", snapshot.get("contentHtml"));
    assertEquals(Boolean.TRUE, snapshot.get("advancedMode"));
    assertEquals("priority", snapshot.get("sortBy"));
    assertEquals(Boolean.TRUE, snapshot.get("reversed"));
  }

  @Test
  void count_whenUploadsRequested_expectBadRequest() {
    RecordingQueuePagePort queuePagePort = new RecordingQueuePagePort();
    RecordingQueueCompletionPort queueCompletionPort = new RecordingQueueCompletionPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            queuePagePort,
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            queueCompletionPort);
    Map<String, List<String>> parameters = orderedParameters(Map.entry("page", List.of("uploads")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.count(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'page' must be 'downloads' for this endpoint.", error.getMessage());
    assertEquals(0, queuePagePort.countPageRequests);
    assertEquals(List.of(), queueCompletionPort.startedSides);
  }

  @Test
  void removeRequests_whenLegacyIdentifierParametersProvided_expectSelectionOrderPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("identifier-1", List.of("download-2"))));

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
  }

  @Test
  void removeRequests_whenIdentifierFieldsOutOfOrder_expectSuffixOrderPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(
                Map.entry("identifier-10", List.of("download-10")),
                Map.entry("identifier-2", List.of("download-2")),
                Map.entry("identifier-1", List.of("download-1"))));

    assertEquals(
        List.of("download-1", "download-2", "download-10"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(3, result.get("identifierCount"));
  }

  @Test
  void removeRequests_whenRepeatedIdentifierParameterProvided_expectAllIdentifiersPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(Map.entry("identifier", List.of("download-1", "download-2"))));

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
  }

  @Test
  void createDirectDownload_whenRequested_expectDirectForeverQueueRequest() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createDirectDownload(
            orderedParameters(
                Map.entry("fetchUri", List.of("KSK@direct-download")),
                Map.entry("filterData", List.of("true")),
                Map.entry("expectedMimeType", List.of("text/plain"))));

    assertEquals(
        new QueueDownloadRequest(
            "KSK@direct-download", true, "text/plain", "forever", "direct", null),
        queueDownloadPort.lastRequest);
    assertEquals("create_direct_download", result.get("operation"));
    assertEquals("KSK@direct-download", result.get("fetchUri"));
    assertEquals(Boolean.TRUE, result.get("filterData"));
    assertEquals("text/plain", result.get("expectedMimeType"));
    assertEquals("direct", result.get("returnType"));
  }

  @Test
  void createDirectDownload_whenFilterDataCheckboxValuePresent_expectTrue() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createDirectDownload(
            orderedParameters(
                Map.entry("fetchUri", List.of("KSK@direct-download")),
                Map.entry("filterData", List.of("on"))));

    assertEquals(Boolean.TRUE, result.get("filterData"));
    assertEquals(Boolean.TRUE, queueDownloadPort.lastRequest.filterData());
  }

  @Test
  void createDirectDownload_whenFetchUriMalformed_expectBadRequest() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(Map.entry("fetchUri", List.of("http://example.com/")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createDirectDownload(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'fetchUri' must be a valid fetch URI.", error.getMessage());
    assertNull(queueDownloadPort.lastRequest);
  }

  @Test
  void changePriority_whenPriorityMalformed_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")),
            Map.entry("priority", List.of("fast")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.changePriority(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
  }

  @Test
  void changePriority_whenPriorityWithinSupportedRange_expectMutationSummary() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")),
            Map.entry("identifier-1", List.of("download-2")),
            Map.entry("priority", List.of("3")));

    Map<String, Object> result = handler.changePriority(parameters);

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals((short) 3, queueMutationPort.lastPriorityClass);
    assertEquals("change_priority", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
    assertEquals((short) 3, result.get("priority"));
  }

  @Test
  void changePriority_whenPriorityOutsideSupportedRange_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")), Map.entry("priority", List.of("99")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.changePriority(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'priority' must be between 0 and 6.", error.getMessage());
  }

  @Test
  void restartRequests_whenDisableFilterCheckboxValuePresent_expectTrue() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.restartRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("disableFilterData", List.of("disableFilterData"))));

    assertEquals("restart", result.get("operation"));
    assertEquals(Boolean.TRUE, result.get("disableFilterData"));
    assertEquals(Boolean.TRUE, queueMutationPort.lastDisableFilterData);
  }

  @Test
  void restartRequests_whenDisableFilterCheckboxRepeated_expectTrue() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.restartRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("disableFilterData", List.of("disableFilterData", "disableFilterData"))));

    assertEquals("restart", result.get("operation"));
    assertEquals(Boolean.TRUE, result.get("disableFilterData"));
    assertEquals(Boolean.TRUE, queueMutationPort.lastDisableFilterData);
  }

  @SafeVarargs
  private static Map<String, List<String>> orderedParameters(
      Map.Entry<String, List<String>>... entries) {
    LinkedHashMap<String, List<String>> parameters = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, List<String>> entry : entries) {
      parameters.put(entry.getKey(), entry.getValue());
    }
    return parameters;
  }

  private static final class RecordingQueuePagePort implements QueuePagePort {
    private QueuePageSnapshot pageSnapshot = new QueuePageSnapshot("Queue", "<div></div>");
    private QueuePageRequest lastPageRequest;
    private int countPageRequests;

    @Override
    public QueuePageSnapshot renderPage(QueuePageRequest request) {
      lastPageRequest = request;
      return pageSnapshot;
    }

    @Override
    public QueuePageSnapshot renderCountPage(boolean uploads) {
      countPageRequests++;
      return new QueuePageSnapshot("Count", "<div>count</div>");
    }

    @Override
    public String renderKeyList(boolean uploads) {
      return "CHK@alpha\nCHK@beta\n";
    }
  }

  private static final class RecordingQueueMutationPort implements QueueMutationPort {
    private List<String> lastIdentifiers = List.of();
    private boolean lastDisableFilterData;
    private short lastPriorityClass;

    @Override
    public void removeRequests(List<String> identifiers) {
      lastIdentifiers = identifiers;
    }

    @Override
    public void restartRequests(List<String> identifiers, boolean disableFilterData) {
      lastIdentifiers = identifiers;
      lastDisableFilterData = disableFilterData;
    }

    @Override
    public void changePriority(List<String> identifiers, short newPriorityClass) {
      lastIdentifiers = identifiers;
      lastPriorityClass = newPriorityClass;
    }

    @Override
    public void removeFinishedUploads() {
      throw new UnsupportedOperationException(
          "Queue cleanup is not exercised by this test double.");
    }

    @Override
    public void removeFinishedDownloads() {
      throw new UnsupportedOperationException(
          "Queue cleanup is not exercised by this test double.");
    }
  }

  private static final class RecordingQueueDownloadPort implements QueueDownloadPort {
    private QueueDownloadRequest lastRequest;

    @Override
    public boolean isDiskDownloadDisabled() {
      return false;
    }

    @Override
    public void enqueueDownload(QueueDownloadRequest request) {
      lastRequest = request;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class FixedQueueSupportPort implements QueueSupportPort {
    private final boolean enabled;

    private FixedQueueSupportPort(boolean enabled) {
      this.enabled = enabled;
    }

    @Override
    public boolean isQueueBackendEnabled() {
      return enabled;
    }

    @Override
    public QueuePersistenceStatusSnapshot persistenceStatus() {
      return new QueuePersistenceStatusSnapshot(false, false, null, null);
    }

    @Override
    public void beginPanic() {
      throw new UnsupportedOperationException("Panic flows are not exercised by this test double.");
    }

    @Override
    public void finishPanic() {
      throw new UnsupportedOperationException("Panic flows are not exercised by this test double.");
    }
  }

  private static final class RecordingQueueCompletionPort implements QueueCompletionPort {
    private final List<Boolean> startedSides = new java.util.ArrayList<>();

    @Override
    public void ensureTrackingStarted(boolean uploads) {
      startedSides.add(uploads);
    }
  }
}

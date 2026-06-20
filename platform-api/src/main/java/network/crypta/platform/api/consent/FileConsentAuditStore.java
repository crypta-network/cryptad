package network.crypta.platform.api.consent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Append-only JSON-lines consent audit store with an in-memory read index.
 *
 * <p>This store writes each normalized {@link ConsentAuditEvent} as one UTF-8 JSON line and mirrors
 * the retained events in an {@link InMemoryConsentAuditStore} for efficient route reads. It is
 * intended for local operator evidence and support summaries, not as a durable authorization
 * source. Consent approval checks use the decision cache in {@link ConsentService}; this class only
 * records the result.
 *
 * <p>Writes create the parent directory on demand and are synchronized so one router instance
 * preserves append order. Existing file contents are not replayed into the in-memory index at
 * startup, which keeps the current implementation process-local for reads while still leaving a
 * best-effort JSON-lines trail on disk.
 */
public final class FileConsentAuditStore implements ConsentAuditStore {
  private final Path auditLog;
  private final InMemoryConsentAuditStore index = new InMemoryConsentAuditStore();

  /**
   * Creates a store backed by the supplied JSON-lines path.
   *
   * <p>The path may point to a file in a directory that does not yet exist. The first append
   * creates parent directories when needed.
   *
   * @param auditLog destination JSON-lines file for appended consent audit events
   * @throws NullPointerException when {@code auditLog} is null
   */
  public FileConsentAuditStore(Path auditLog) {
    this.auditLog = Objects.requireNonNull(auditLog, "auditLog");
  }

  /**
   * Appends one audit event to the JSON-lines file and read index.
   *
   * <p>The event is written before it is added to the in-memory index. If filesystem persistence
   * fails, the method throws and the read index is not advanced, keeping this instance internally
   * consistent.
   *
   * @param event redacted consent audit event to append
   * @throws IllegalStateException when the event cannot be written to the audit log
   */
  @Override
  public synchronized void append(ConsentAuditEvent event) {
    try {
      Path parent = auditLog.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      Files.writeString(
          auditLog,
          PlatformApiJsonWriter.write(event.toJsonValue()) + System.lineSeparator(),
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.APPEND);
      index.append(event);
    } catch (IOException exception) {
      throw new IllegalStateException("Failed to append consent audit event.", exception);
    }
  }

  /**
   * Lists retained events from the process-local read index.
   *
   * <p>The result reflects events appended through this store instance. It does not parse
   * historical JSON-lines data that may already exist on disk before the instance is created.
   *
   * @param appId app id to filter by, or {@code null} for all retained indexed events
   * @return retained events in append order for this process
   */
  @Override
  public synchronized List<ConsentAuditEvent> list(String appId) {
    return index.list(appId);
  }
}

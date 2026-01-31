package network.crypta.clients.fcp;

import java.io.File;
import java.util.Arrays;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Parameter bundle describing a {@link ClientGet} request status snapshot.
 *
 * <p>This record mirrors the inputs required to construct a {@link DownloadRequestStatus} from the
 * current state of a {@link ClientGet} request. It is intentionally immutable and performs no
 * validation, so callers can reuse it across status refreshes without altering behavior.
 */
public final class ClientGetStatusSnapshot {
  private final String identifier;
  private final ClientRequest.Persistence persistence;
  private final boolean started;
  private final boolean finished;
  private final boolean succeeded;
  private final SimpleProgressMessage progressPending;
  private final GetFailedMessage failedMessage;
  private final String foundDataMimeType;
  private final long foundDataLength;
  private final File destinationFile;
  private final Bucket dataBucket;
  private final FetchContext fetchContext;
  private final short priorityClass;
  private final CompatibilityMode[] compatModes;
  private final byte[] splitfileKey;
  private final FreenetURI uri;
  private final boolean dontCompress;

  /**
   * Creates a snapshot containing the current request metadata.
   *
   * @param identifier request identifier to report.
   * @param persistence persistence mode for the request.
   * @param started whether the request has started.
   * @param finished whether the request has finished.
   * @param succeeded whether the request has succeeded.
   * @param progressPending last recorded progress snapshot, if any.
   * @param failedMessage cached failure message, if any.
   * @param foundDataMimeType MIME type discovered for the data.
   * @param foundDataLength data length recorded for the request.
   * @param destinationFile destination file for disk requests.
   * @param dataBucket bucket containing result data.
   * @param fetchContext fetch context providing filter and MIME overrides.
   * @param priorityClass scheduler priority class.
   * @param compatModes compatibility modes observed for the request.
   * @param splitfileKey splitfile crypto key override, if any.
   * @param uri request URI to report.
   * @param dontCompress whether reinsertion should skip compression.
   */
  public ClientGetStatusSnapshot(
      String identifier,
      ClientRequest.Persistence persistence,
      boolean started,
      boolean finished,
      boolean succeeded,
      SimpleProgressMessage progressPending,
      GetFailedMessage failedMessage,
      String foundDataMimeType,
      long foundDataLength,
      File destinationFile,
      Bucket dataBucket,
      FetchContext fetchContext,
      short priorityClass,
      CompatibilityMode[] compatModes,
      byte[] splitfileKey,
      FreenetURI uri,
      boolean dontCompress) {
    this.identifier = identifier;
    this.persistence = persistence;
    this.started = started;
    this.finished = finished;
    this.succeeded = succeeded;
    this.progressPending = progressPending;
    this.failedMessage = failedMessage;
    this.foundDataMimeType = foundDataMimeType;
    this.foundDataLength = foundDataLength;
    this.destinationFile = destinationFile;
    this.dataBucket = dataBucket;
    this.fetchContext = fetchContext;
    this.priorityClass = priorityClass;
    this.compatModes = compatModes;
    this.splitfileKey = splitfileKey;
    this.uri = uri;
    this.dontCompress = dontCompress;
  }

  public String identifier() {
    return identifier;
  }

  public ClientRequest.Persistence persistence() {
    return persistence;
  }

  public boolean started() {
    return started;
  }

  public boolean finished() {
    return finished;
  }

  public boolean succeeded() {
    return succeeded;
  }

  public SimpleProgressMessage progressPending() {
    return progressPending;
  }

  public GetFailedMessage failedMessage() {
    return failedMessage;
  }

  public String foundDataMimeType() {
    return foundDataMimeType;
  }

  public long foundDataLength() {
    return foundDataLength;
  }

  public File destinationFile() {
    return destinationFile;
  }

  public Bucket dataBucket() {
    return dataBucket;
  }

  public FetchContext fetchContext() {
    return fetchContext;
  }

  public short priorityClass() {
    return priorityClass;
  }

  public CompatibilityMode[] compatModes() {
    return compatModes;
  }

  public byte[] splitfileKey() {
    return splitfileKey;
  }

  public FreenetURI uri() {
    return uri;
  }

  public boolean dontCompress() {
    return dontCompress;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ClientGetStatusSnapshot otherSnapshot)) {
      return false;
    }
    return started == otherSnapshot.started
        && finished == otherSnapshot.finished
        && succeeded == otherSnapshot.succeeded
        && foundDataLength == otherSnapshot.foundDataLength
        && priorityClass == otherSnapshot.priorityClass
        && dontCompress == otherSnapshot.dontCompress
        && java.util.Objects.equals(identifier, otherSnapshot.identifier)
        && persistence == otherSnapshot.persistence
        && java.util.Objects.equals(progressPending, otherSnapshot.progressPending)
        && java.util.Objects.equals(failedMessage, otherSnapshot.failedMessage)
        && java.util.Objects.equals(foundDataMimeType, otherSnapshot.foundDataMimeType)
        && java.util.Objects.equals(destinationFile, otherSnapshot.destinationFile)
        && java.util.Objects.equals(dataBucket, otherSnapshot.dataBucket)
        && java.util.Objects.equals(fetchContext, otherSnapshot.fetchContext)
        && Arrays.equals(compatModes, otherSnapshot.compatModes)
        && Arrays.equals(splitfileKey, otherSnapshot.splitfileKey)
        && java.util.Objects.equals(uri, otherSnapshot.uri);
  }

  @Override
  public int hashCode() {
    int result =
        java.util.Objects.hash(
            identifier,
            persistence,
            started,
            finished,
            succeeded,
            progressPending,
            failedMessage,
            foundDataMimeType,
            foundDataLength,
            destinationFile,
            dataBucket,
            fetchContext,
            priorityClass,
            uri,
            dontCompress);
    result = 31 * result + Arrays.hashCode(compatModes);
    result = 31 * result + Arrays.hashCode(splitfileKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "ClientGetStatusSnapshot["
        + "identifier="
        + identifier
        + ", persistence="
        + persistence
        + ", started="
        + started
        + ", finished="
        + finished
        + ", succeeded="
        + succeeded
        + ", progressPending="
        + progressPending
        + ", failedMessage="
        + failedMessage
        + ", foundDataMimeType="
        + foundDataMimeType
        + ", foundDataLength="
        + foundDataLength
        + ", destinationFile="
        + destinationFile
        + ", dataBucket="
        + dataBucket
        + ", fetchContext="
        + fetchContext
        + ", priorityClass="
        + priorityClass
        + ", compatModes="
        + Arrays.toString(compatModes)
        + ", splitfileKey="
        + Arrays.toString(splitfileKey)
        + ", uri="
        + uri
        + ", dontCompress="
        + dontCompress
        + ']';
  }
}

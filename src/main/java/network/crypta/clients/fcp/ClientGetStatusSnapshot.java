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
@SuppressWarnings("ArrayRecordComponent")
public record ClientGetStatusSnapshot(
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

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other
        instanceof
        ClientGetStatusSnapshot(
            String otherIdentifier,
            ClientRequest.Persistence otherPersistence,
            boolean otherStarted,
            boolean otherFinished,
            boolean otherSucceeded,
            SimpleProgressMessage otherProgressPending,
            GetFailedMessage otherFailedMessage,
            String otherFoundDataMimeType,
            long otherFoundDataLength,
            File otherDestinationFile,
            Bucket otherDataBucket,
            FetchContext otherFetchContext,
            short otherPriorityClass,
            CompatibilityMode[] otherCompatModes,
            byte[] otherSplitfileKey,
            FreenetURI otherUri,
            boolean otherDontCompress))) {
      return false;
    }
    return started == otherStarted
        && finished == otherFinished
        && succeeded == otherSucceeded
        && foundDataLength == otherFoundDataLength
        && priorityClass == otherPriorityClass
        && dontCompress == otherDontCompress
        && java.util.Objects.equals(identifier, otherIdentifier)
        && persistence == otherPersistence
        && java.util.Objects.equals(progressPending, otherProgressPending)
        && java.util.Objects.equals(failedMessage, otherFailedMessage)
        && java.util.Objects.equals(foundDataMimeType, otherFoundDataMimeType)
        && java.util.Objects.equals(destinationFile, otherDestinationFile)
        && java.util.Objects.equals(dataBucket, otherDataBucket)
        && java.util.Objects.equals(fetchContext, otherFetchContext)
        && Arrays.equals(compatModes, otherCompatModes)
        && Arrays.equals(splitfileKey, otherSplitfileKey)
        && java.util.Objects.equals(uri, otherUri);
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

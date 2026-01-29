package network.crypta.clients.fcp;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.FreenetURI;
import org.jetbrains.annotations.NotNull;

/**
 * Parameter bundle containing download-specific status metadata.
 *
 * <p>This record complements {@link RequestStatusSnapshot} by packaging fields that are unique to
 * {@link DownloadRequestStatus}.
 *
 * @param outcome completion details such as MIME type and failure descriptions.
 * @param destFilename destination file requested by the client, if any.
 * @param compatModes compatibility modes observed for splitfiles.
 * @param splitfileKey splitfile crypto key override, if provided.
 * @param uri request URI, including any redirects.
 * @param overriddenDataType whether the client overrode MIME settings.
 * @param dontCompress whether reinsertion should skip compression.
 */
@SuppressWarnings("ArrayRecordComponent")
public record DownloadRequestStatusDetails(
    DownloadOutcomeInfo outcome,
    File destFilename,
    CompatibilityMode[] compatModes,
    byte[] splitfileKey,
    FreenetURI uri,
    boolean overriddenDataType,
    boolean dontCompress) {

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other
        instanceof
        DownloadRequestStatusDetails(
            DownloadOutcomeInfo otherOutcome,
            File otherDestFilename,
            CompatibilityMode[] otherCompatModes,
            byte[] otherSplitfileKey,
            FreenetURI otherUri,
            boolean otherOverriddenDataType,
            boolean otherDontCompress))) {
      return false;
    }
    return overriddenDataType == otherOverriddenDataType
        && dontCompress == otherDontCompress
        && Objects.equals(outcome, otherOutcome)
        && Objects.equals(destFilename, otherDestFilename)
        && Arrays.equals(compatModes, otherCompatModes)
        && Arrays.equals(splitfileKey, otherSplitfileKey)
        && Objects.equals(uri, otherUri);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(outcome, destFilename, uri, overriddenDataType, dontCompress);
    result = 31 * result + Arrays.hashCode(compatModes);
    result = 31 * result + Arrays.hashCode(splitfileKey);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "DownloadRequestStatusDetails["
        + "outcome="
        + outcome
        + ", destFilename="
        + destFilename
        + ", compatModes="
        + Arrays.toString(compatModes == null ? null : compatModes.clone())
        + ", splitfileKey="
        + Arrays.toString(splitfileKey == null ? null : splitfileKey.clone())
        + ", uri="
        + uri
        + ", overriddenDataType="
        + overriddenDataType
        + ", dontCompress="
        + dontCompress
        + ']';
  }
}

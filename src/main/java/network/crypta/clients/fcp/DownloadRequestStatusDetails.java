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
 * <p>This value object complements {@link RequestStatusSnapshot} by packaging fields that are
 * unique to {@link DownloadRequestStatus}.
 */
@SuppressWarnings("java:S6206")
public final class DownloadRequestStatusDetails {
  private final DownloadOutcomeInfo outcome;
  private final File destFilename;
  private final CompatibilityMode[] compatModes;
  private final byte[] splitfileKey;
  private final FreenetURI uri;
  private final boolean overriddenDataType;
  private final boolean dontCompress;

  /**
   * Creates a download status detail bundle.
   *
   * @param outcome completion details such as MIME type and failure descriptions.
   * @param destFilename destination file requested by the client, if any.
   * @param compatModes compatibility modes observed for splitfiles.
   * @param splitfileKey splitfile crypto key override, if provided.
   * @param uri request URI, including any redirects.
   * @param overriddenDataType whether the client overrode MIME settings.
   * @param dontCompress whether reinsertion should skip compression.
   */
  public DownloadRequestStatusDetails(
      DownloadOutcomeInfo outcome,
      File destFilename,
      CompatibilityMode[] compatModes,
      byte[] splitfileKey,
      FreenetURI uri,
      boolean overriddenDataType,
      boolean dontCompress) {
    this.outcome = outcome;
    this.destFilename = destFilename;
    this.compatModes = compatModes;
    this.splitfileKey = splitfileKey;
    this.uri = uri;
    this.overriddenDataType = overriddenDataType;
    this.dontCompress = dontCompress;
  }

  public DownloadOutcomeInfo outcome() {
    return outcome;
  }

  public File destFilename() {
    return destFilename;
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

  public boolean overriddenDataType() {
    return overriddenDataType;
  }

  public boolean dontCompress() {
    return dontCompress;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof DownloadRequestStatusDetails details)) {
      return false;
    }
    return overriddenDataType == details.overriddenDataType
        && dontCompress == details.dontCompress
        && Objects.equals(outcome, details.outcome)
        && Objects.equals(destFilename, details.destFilename)
        && Arrays.equals(compatModes, details.compatModes)
        && Arrays.equals(splitfileKey, details.splitfileKey)
        && Objects.equals(uri, details.uri);
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

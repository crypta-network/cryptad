package network.crypta.client;

import java.util.Arrays;
import java.util.Objects;

/** Splitfile crypto parameters and key specification flags. */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class SplitfileCryptoParams {
  private final byte splitfileCryptoAlgorithm;
  private final byte[] splitfileCryptoKey;
  private final boolean specifySplitfileKey;

  public SplitfileCryptoParams(
      byte splitfileCryptoAlgorithm, byte[] splitfileCryptoKey, boolean specifySplitfileKey) {
    this.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
    this.splitfileCryptoKey = splitfileCryptoKey;
    this.specifySplitfileKey = specifySplitfileKey;
  }

  public byte splitfileCryptoAlgorithm() {
    return splitfileCryptoAlgorithm;
  }

  public byte[] splitfileCryptoKey() {
    return splitfileCryptoKey;
  }

  public boolean specifySplitfileKey() {
    return specifySplitfileKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof SplitfileCryptoParams other)) {
      return false;
    }
    return splitfileCryptoAlgorithm == other.splitfileCryptoAlgorithm
        && specifySplitfileKey == other.specifySplitfileKey
        && Arrays.equals(splitfileCryptoKey, other.splitfileCryptoKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        splitfileCryptoAlgorithm, Arrays.hashCode(splitfileCryptoKey), specifySplitfileKey);
  }

  @Override
  public String toString() {
    String keyString = (splitfileCryptoKey == null) ? "null" : Arrays.toString(splitfileCryptoKey);
    return "SplitfileCryptoParams["
        + "splitfileCryptoAlgorithm="
        + splitfileCryptoAlgorithm
        + ", splitfileCryptoKey="
        + keyString
        + ", specifySplitfileKey="
        + specifySplitfileKey
        + "]";
  }
}

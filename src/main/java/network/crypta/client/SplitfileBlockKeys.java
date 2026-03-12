package network.crypta.client;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.ClientCHK;

/** Data and check block keys used by a splitfile. */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class SplitfileBlockKeys {
  private final ClientCHK[] dataURIs;
  private final ClientCHK[] checkURIs;

  public SplitfileBlockKeys(ClientCHK[] dataURIs, ClientCHK[] checkURIs) {
    this.dataURIs = dataURIs;
    this.checkURIs = checkURIs;
  }

  public ClientCHK[] dataURIs() {
    return dataURIs;
  }

  public ClientCHK[] checkURIs() {
    return checkURIs;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof SplitfileBlockKeys other)) {
      return false;
    }
    return Arrays.equals(dataURIs, other.dataURIs) && Arrays.equals(checkURIs, other.checkURIs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(Arrays.hashCode(dataURIs), Arrays.hashCode(checkURIs));
  }

  @Override
  public String toString() {
    return "SplitfileBlockKeys["
        + "dataURIs="
        + Arrays.toString(dataURIs)
        + ", checkURIs="
        + Arrays.toString(checkURIs)
        + "]";
  }
}

package network.crypta.node.updater;

import java.util.Objects;

/** Package metadata for a single distributable artifact. */
public final class PackageSpec {
  private final String chk;
  private final Long size;
  private final String storeUrl;

  public PackageSpec(String chk, Long size, String storeUrl) {
    this.chk = chk;
    this.size = size;
    this.storeUrl = storeUrl;
  }

  public String getChk() {
    return chk;
  }

  public Long getSize() {
    return size;
  }

  public String getStoreUrl() {
    return storeUrl;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PackageSpec that)) {
      return false;
    }
    return Objects.equals(chk, that.chk)
        && Objects.equals(size, that.size)
        && Objects.equals(storeUrl, that.storeUrl);
  }

  @Override
  public int hashCode() {
    return Objects.hash(chk, size, storeUrl);
  }

  @Override
  public String toString() {
    return "PackageSpec{"
        + "chk='"
        + chk
        + '\''
        + ", size="
        + size
        + ", storeUrl='"
        + storeUrl
        + '\''
        + '}';
  }
}

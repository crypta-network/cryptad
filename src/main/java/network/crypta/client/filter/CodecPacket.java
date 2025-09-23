package network.crypta.client.filter;

import java.util.Arrays;

public class CodecPacket {
  protected byte[] payload = null;

  CodecPacket(byte[] payload) {
    this.payload = payload;
  }

  public byte[] toArray() {
    return payload;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(payload);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (!(obj instanceof CodecPacket other)) return false;
    return Arrays.equals(payload, other.payload);
  }
}

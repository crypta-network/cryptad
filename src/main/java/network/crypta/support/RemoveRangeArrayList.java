package network.crypta.support;

import java.io.Serial;
import java.util.ArrayList;

public class RemoveRangeArrayList<T> extends ArrayList<T> {

  @Serial private static final long serialVersionUID = -1L;

  public RemoveRangeArrayList(int capacity) {
    super(capacity);
  }

  @Override
  public void removeRange(int fromIndex, int toIndex) {
    super.removeRange(fromIndex, toIndex);
  }
}

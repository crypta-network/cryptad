package network.crypta.io.comm;

import java.lang.ref.WeakReference;

public interface MessageSource {
  Peer getPeer();

  long getBootID();

  WeakReference<? extends MessageSource> getWeakRef();
}

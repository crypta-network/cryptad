package network.crypta.clients.http.bridge;

import java.net.URI;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.HttpShellRuntimeSupport;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.TempBucketFactory;

/**
 * Adapter that exposes {@link SimpleToadletServer} through the runtime-owned {@link
 * HttpShellContainer} seam.
 *
 * <p>This class is intentionally thin. It does not reinterpret configuration, lifecycle, or
 * toadlet-registration behavior; it forwards those operations directly to the wrapped legacy shell
 * server so the refactor remains dependency-oriented rather than behavior-changing. The adapter
 * exists to keep the knowledge of the concrete shell type inside this bridge package while the rest
 * of runtime code works only with the narrower seam.
 *
 * <p>Most methods are direct pass-through delegations. The only notable translation is {@link
 * #markStartupPrngReady()}, which hides the concrete startup-toadlet access pattern from callers so
 * bootstrap code no longer reaches into the legacy shell's internal startup page structure.
 */
final class SimpleToadletServerHttpShellContainer implements HttpShellContainer {
  /** Wrapped legacy shell server that performs all concrete HTTP host work. */
  private final SimpleToadletServer delegate;

  /**
   * Creates a runtime-facing wrapper around an existing legacy shell server.
   *
   * <p>The caller retains responsibility for choosing and constructing the concrete server
   * instance. This adapter simply stores that instance and forwards all later operations to it so
   * the surrounding runtime code can depend on {@link HttpShellContainer} instead of the concrete
   * legacy class.
   *
   * @param delegate concrete legacy shell server that should back every delegated seam operation
   */
  SimpleToadletServerHttpShellContainer(SimpleToadletServer delegate) {
    this.delegate = delegate;
  }

  @Override
  public void start() {
    delegate.start();
  }

  @Override
  public void setRuntimeSupport(HttpShellRuntimeSupport runtimeSupport) {
    if (!(runtimeSupport
        instanceof network.crypta.clients.http.HttpShellRuntimeSupport legacySupport)) {
      throw new IllegalArgumentException(
          "SimpleToadletServerHttpShellContainer requires runtimeSupport to also implement "
              + "network.crypta.clients.http.HttpShellRuntimeSupport; pair custom "
              + "HttpShellRuntimeSupportFactory bindings with a compatible "
              + "HttpShellContainerFactory");
    }
    delegate.setRuntimeSupport(legacySupport);
  }

  @Override
  public void setBucketFactory(TempBucketFactory tempBucketFactory) {
    delegate.setBucketFactory(tempBucketFactory);
  }

  @Override
  public boolean isEnabled() {
    return delegate.isEnabled();
  }

  @Override
  public void finishStart() {
    delegate.finishStart();
  }

  @Override
  public void createFproxy() {
    delegate.createFproxy();
  }

  @Override
  public void removeStartupToadlet() {
    delegate.removeStartupToadlet();
  }

  @Override
  public void markStartupPrngReady() {
    delegate.getStartupToadlet().setIsPRNGReady();
  }

  @Override
  public boolean isAdvancedModeEnabled() {
    return delegate.isAdvancedModeEnabled();
  }

  @Override
  public boolean isFProxyJavascriptEnabled() {
    return delegate.isFProxyJavascriptEnabled();
  }

  @Override
  public boolean isLinkExcepted(URI link) {
    return delegate.isLinkExcepted(link);
  }

  @Override
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
    return delegate.addFormChild(parentNode, target, name);
  }
}

package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Java implementation backing {@code com.jthemedetecor.PortalThemeDetector}.
 *
 * <p>This keeps the public API expected by the launcher while avoiding Kotlin runtime dependencies.
 * It delegates theme probing/listener registration to the upstream detector.
 */
public class PortalThemeDetectorImpl implements Closeable {
  private final OsThemeDetector delegate;

  public PortalThemeDetectorImpl() {
    this(OsThemeDetector.getDetector());
  }

  PortalThemeDetectorImpl(OsThemeDetector delegate) {
    this.delegate = Objects.requireNonNull(delegate);
  }

  public boolean isDark() {
    return delegate.isDark();
  }

  public void registerListener(Consumer<Boolean> darkThemeListener) {
    delegate.registerListener(darkThemeListener);
  }

  public void removeListener(Consumer<Boolean> darkThemeListener) {
    delegate.removeListener(darkThemeListener);
  }

  @Override
  public void close() throws IOException {
    if (delegate instanceof Closeable closeable) {
      closeable.close();
    }
  }
}

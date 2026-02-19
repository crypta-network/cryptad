package com.jthemedetecor;

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Consumer;
import network.crypta.launcher.PortalThemeDetectorImpl;

/**
 * Thin compatibility stub that keeps the subclass inside the original package so it can extend
 * OsThemeDetector (its constructor is package-private). The implementation lives in
 * network.crypta.launcher.PortalThemeDetectorImpl to avoid split ownership.
 */
public class PortalThemeDetector extends OsThemeDetector implements Closeable {
  private final PortalThemeDetectorImpl impl;

  public PortalThemeDetector() {
    this(new PortalThemeDetectorImpl());
  }

  public PortalThemeDetector(PortalThemeDetectorImpl impl) {
    this.impl = Objects.requireNonNull(impl);
  }

  @Override
  public boolean isDark() {
    return impl.isDark();
  }

  @Override
  public void registerListener(Consumer<Boolean> darkThemeListener) {
    impl.registerListener(darkThemeListener);
  }

  @Override
  public void removeListener(Consumer<Boolean> darkThemeListener) {
    impl.removeListener(darkThemeListener);
  }

  @Override
  public void close() throws IOException {
    impl.close();
  }
}

package com.jthemedetecor

import java.io.Closeable
import java.util.function.Consumer
import network.crypta.launcher.PortalThemeDetectorImpl

/**
 * Thin compatibility stub that keeps the subclass inside the original package so it can extend
 * OsThemeDetector (its constructor is package‑private). The implementation lives in
 * network.crypta.launcher.PortalThemeDetectorImpl to avoid split ownership.
 */
class PortalThemeDetector(private val impl: PortalThemeDetectorImpl = PortalThemeDetectorImpl()) :
  OsThemeDetector(), Closeable by impl {
  override fun isDark(): Boolean = impl.isDark()

  override fun registerListener(darkThemeListener: Consumer<Boolean>) {
    impl.registerListener(darkThemeListener)
  }

  override fun removeListener(darkThemeListener: Consumer<Boolean>?) {
    impl.removeListener(darkThemeListener)
  }
}

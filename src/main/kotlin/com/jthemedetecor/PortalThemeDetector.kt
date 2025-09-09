package com.jthemedetecor

import java.io.Closeable
import java.util.function.Consumer

/**
 * Thin compatibility stub that keeps the subclass inside the original package so it can extend
 * OsThemeDetector (its constructor is package‑private). The implementation lives in
 * network.crypta.launcher.PortalThemeDetectorImpl to avoid split ownership.
 */
class PortalThemeDetector : OsThemeDetector(), Closeable {
  private val impl = network.crypta.launcher.PortalThemeDetectorImpl()

  override fun isDark(): Boolean = impl.isDark()

  override fun registerListener(darkThemeListener: Consumer<Boolean>) {
    impl.registerListener(darkThemeListener)
  }

  override fun removeListener(darkThemeListener: Consumer<Boolean>?) {
    impl.removeListener(darkThemeListener)
  }

  override fun close() {
    impl.close()
  }
}

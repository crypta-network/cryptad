package network.crypta.tools;

import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;

/**
 * Diagnostic utility that prints resolved Cryptad runtime directories.
 *
 * <p>This helper is intended for troubleshooting environment-dependent path resolution without
 * starting the full daemon. It evaluates service-mode detection through {@link AppEnv} and then
 * resolves directories using the same strategy classes used by normal startup: {@link ServiceDirs}
 * for service mode and {@link AppDirs} for user mode. Output is written to standard output as
 * simple {@code key=value} lines so shell scripts and test harnesses can parse it
 * deterministically.
 *
 * <p>The printed values include configuration, data, cache, runtime, and logs directories, along
 * with the selected mode. The class is stateless and provides only static behavior; it is not
 * designed for concurrent shared state or long-lived reuse.
 */
@SuppressWarnings("java:S106")
public final class PrintDirs {
  private PrintDirs() {}

  static void main() {
    AppEnv appEnv = new AppEnv(System.getenv());
    System.out.println("cryptad.service.mode=" + System.getProperty("cryptad.service.mode"));
    if (appEnv.isServiceMode()) {
      Resolved r = new ServiceDirs().resolve();
      System.out.println("mode=service");
      printDirs(r);
    } else {
      Resolved r = new AppDirs().resolve();
      System.out.println("mode=user");
      printDirs(r);
    }
  }

  private static void printDirs(Resolved resolved) {
    System.out.println("configDir=" + resolved.configDir());
    System.out.println("dataDir=" + resolved.dataDir());
    System.out.println("cacheDir=" + resolved.cacheDir());
    System.out.println("runDir=" + resolved.runDir());
    System.out.println("logsDir=" + resolved.logsDir());
  }
}

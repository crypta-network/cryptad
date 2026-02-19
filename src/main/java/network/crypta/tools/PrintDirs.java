package network.crypta.tools;

import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;

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

package network.crypta.client.async;

import java.util.List;
import network.crypta.keys.ClientSSKBlock;

/** Builds plans for handling successful or discovered USK editions. */
final class USKSuccessPlanner {
  static final class SuccessPlan {
    boolean decode;
    long curLatest;
    boolean registerNow;
    List<USKAttempt> killAttempts;
  }

  static final class FoundPlan {
    boolean decode;
    List<USKAttempt> killAttempts;
    boolean registerNow;
  }

  SuccessPlan createSuccessPlan(
      boolean decode, long curLatest, boolean registerNow, List<USKAttempt> killAttempts) {
    SuccessPlan plan = new SuccessPlan();
    plan.decode = decode;
    plan.curLatest = curLatest;
    plan.registerNow = registerNow;
    plan.killAttempts = killAttempts;
    return plan;
  }

  FoundPlan createFoundPlan(boolean decode, boolean registerNow, List<USKAttempt> killAttempts) {
    FoundPlan plan = new FoundPlan();
    plan.decode = decode;
    plan.registerNow = registerNow;
    plan.killAttempts = killAttempts;
    return plan;
  }

  static boolean shouldDecode(
      long curLatest, long lastEd, boolean dontUpdate, ClientSSKBlock block) {
    return curLatest >= lastEd && !(dontUpdate && block == null);
  }
}

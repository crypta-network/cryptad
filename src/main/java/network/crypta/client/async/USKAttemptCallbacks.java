package network.crypta.client.async;

import java.util.Random;
import network.crypta.keys.ClientSSKBlock;

/** Callback interface for {@link USKAttempt} lifecycle events. */
interface USKAttemptCallbacks {
  void onDNF(USKAttempt attempt, ClientContext context);

  void onSuccess(
      USKAttempt attempt, boolean dontUpdate, ClientSSKBlock block, ClientContext context);

  void onCancelled(USKAttempt attempt, ClientContext context);

  void onEnterFiniteCooldown(ClientContext context);

  boolean isBackgroundPoll();

  short getProgressPollPriority();

  short getNormalPollPriority();

  boolean shouldAddRandomEditions(Random random, boolean firstLoop);
}

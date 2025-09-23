package network.crypta.client.async;

import network.crypta.keys.ClientSSKBlock;

/** Callback for a USKChecker */
interface USKCheckerCallback {

  /** Data Not Found */
  void onDNF(ClientContext context);

  /**
   * Successfully found the latest version of the key
   *
   * @param block
   */
  void onSuccess(ClientSSKBlock block, ClientContext context);

  /** Error committed by author */
  void onFatalAuthorError(ClientContext context);

  /** Network on our node or on nodes we have been talking to */
  void onNetworkError(ClientContext context);

  /** Request cancelled */
  void onCancelled(ClientContext context);

  /** Get priority to run the request at */
  short getPriority();

  /** Called when we enter a finite cooldown */
  void onEnterFiniteCooldown(ClientContext context);
}

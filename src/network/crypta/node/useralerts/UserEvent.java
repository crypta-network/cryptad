package network.crypta.node.useralerts;

public interface UserEvent extends UserAlert {
	enum Type {
		Announcer(true), GetCompleted, PutCompleted, PutDirCompleted;

		private final boolean unregisterIndefinitely;

		Type(boolean unregisterIndefinetely) {
			this.unregisterIndefinitely = unregisterIndefinetely;
		}

		Type() {
			unregisterIndefinitely = false;
		}

		/**
		 *
		 * @return true if the unregistration of one event of this type
		 *         should prevent future events of the same type from being displayed
		 */
		public boolean unregisterIndefinitely() {
			return unregisterIndefinitely;
		}
	}

	/**
	 *
	 * @return The type of the event
	 */
    Type getEventType();
}

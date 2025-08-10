package network.crypta.config;

public abstract class ConfigCallback<T> {

	/**
	 * Get the current, used value of the config variable.
	 */
	public abstract T get();

	/**
	 * Set the config variable to a new value.
	 * 
	 * @param val
	 *            The new value.
	 * @throws InvalidConfigOptionException
	 *             If the new value is invalid for this particular option.
	 */
	public abstract void set(T val) throws InvalidConfigValueException, NodeNeedRestartException;
	
	public boolean isReadOnly() {
		return false;
	} 
}

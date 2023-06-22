package us.kbase.auth2.lib.config;

import static java.util.Objects.requireNonNull;

import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;

/** A configuration item. A configuration item consists of an action to take, and possibly an item
 * associated with that action.
 * @author gaprice@lbl.gov
 *
 * @param <T> the type of the item, if any, in this configuration item.
 * @param <A> the type of the action in this configuration item.
 */
public class ConfigItem<T, A extends ConfigAction> {
	
	private final T item;
	private final A action;
	
	/** Get a configuration state action that, rather than being a true action, represents the
	 * state of the configuration item.
	 * @param item the item to associate with the action.
	 * @param <T> the type of the item in this configuration item.
	 * @return a new ConfigItem with the state "action".
	 */
	public static <T> ConfigItem<T, State> state(T item) {
		requireNonNull(item, "item");
		return new ConfigItem<>(item, ConfigAction.state());
	}
	
	/** Get an empty configuration state action that, rather than being a true action, represents
	 * the state of the configuration item. This configuration item has no item associated with
	 * the action.
	 * @param <T> the type of the item the empty state represents.
	 * @return an empty ConfigItem with the state "action".
	 */
	public static <T> ConfigItem<T, State> emptyState() {
		return new ConfigItem<>(null, ConfigAction.state());
	}
	
	/** Get a remove action. There is never an item associated with this type of action.
	 * @param <T> the type of the item to be removed.
	 * @return a new ConfigItem with the remove action.
	 */
	public static <T> ConfigItem<T, Action> remove() {
		return new ConfigItem<>(null, ConfigAction.remove());
	}
	
	/** Get an action specifying that no action should be taken. There is never an item associated
	 * with this type of action.
	 * @param <T> the type of the item upon which no action should be taken.
	 * @return a new ConfigItem with a no-op action.
	 */
	public static <T> ConfigItem<T, Action> noAction() {
		return new ConfigItem<>(null, ConfigAction.noAction());
	}
	
	/** Get a set action with an associated item.
	 * @param item the item to associate with the set action.
	 * @param <T> the type of the item in this configuration item.
	 * @return a new ConfigItem with a set action.
	 */
	public static <T> ConfigItem<T, Action> set(T item) {
		requireNonNull(item, "item");
		return new ConfigItem<>(item, ConfigAction.set());
	}

	private ConfigItem(T item, A action) {
		this.item = item;
		this.action = action;
	}

	/** Get the item associated with the action.
	 * @return the item.
	 * @throws IllegalStateException if there is no item.
	 */
	public T getItem() {
		if (item == null) {
			throw new IllegalStateException("getItem() cannot be called on an absent item");
		}
		return item;
	}
	
	/** Returns true if there is an item associated with the config action.
	 * @return true if this ConfigItem contains an item.
	 */
	public boolean hasItem() {
		return item != null;
	}

	/** Get the action associated with this ConfigItem.
	 * @return the action.
	 */
	public A getAction() {
		return action;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("ConfigItem [item=");
		builder.append(item);
		builder.append(", action=");
		builder.append(action);
		builder.append("]");
		return builder.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((action == null) ? 0 : action.hashCode());
		result = prime * result + ((item == null) ? 0 : item.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ConfigItem<?, ?> other = (ConfigItem<?, ?>) obj;
		if (action == null) {
			if (other.action != null) {
				return false;
			}
		} else if (!action.equals(other.action)) {
			return false;
		}
		if (item == null) {
			if (other.item != null) {
				return false;
			}
		} else if (!item.equals(other.item)) {
			return false;
		}
		return true;
	}
}

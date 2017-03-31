package us.kbase.auth2.lib.config;

/** An action to take with relation to a configuration item.
 * @author gaprice@lbl.gov
 *
 */
public interface ConfigAction {
	
	//TODO NOW TEST

	/** Returns true if this ConfigAction simply represents the state of the configuration item.
	 * 
	 * No action is required, but a value for the configuration item may be expected.
	 * @return true if the action is actually a state.
	 */
	public boolean isState();
	
	/** Returns true if no action is required.
	 * @return true if no action is required.
	 */
	public boolean isNoAction();
	
	/** Returns true if this ConfigAction represents a set action - the configuration item should
	 * be set to a new value.
	 * @return true if this action is a set.
	 */
	public boolean isSet();
	
	/** Returns true if this ConfigAction represents a remove action - the configuration item
	 * should be removed from the configuration.
	 * @return true if this action is a remove.
	 */
	public boolean isRemove();
	
	static ConfigState state() {
		return ConfigState.INSTANCE;
	}
	
	static RemoveAction remove() {
		return RemoveAction.INSTANCE;
	}
	
	static NoAction noAction() {
		return NoAction.INSTANCE;
	}
	
	static SetAction set() {
		return SetAction.INSTANCE;
	}
	
	/** A configuration state. 
	 * @author gaprice@lbl.gov
	 *
	 */
	public final static class ConfigState implements ConfigAction {
		
		private static final ConfigState INSTANCE = new ConfigState();
		
		private ConfigState() {}
		
		@Override
		public boolean isRemove() {
			return false;
		}

		@Override
		public boolean isNoAction() {
			return false;
		}

		@Override
		public boolean isSet() {
			return false;
		}
		
		@Override
		public boolean isState() {
			return true;
		}
	}
	
	/** An action, as opposed to a configuration state.
	 * @author gaprice@lbl.gov
	 *
	 */
	public interface Action extends ConfigAction {}
	
	
	/** A remove action.
	 * @author gaprice@lbl.gov
	 *
	 */
	public final class RemoveAction implements Action {
		
		private static final RemoveAction INSTANCE = new RemoveAction();
		
		private RemoveAction() {}

		@Override
		public boolean isRemove() {
			return true;
		}

		@Override
		public boolean isNoAction() {
			return false;
		}

		@Override
		public boolean isSet() {
			return false;
		}

		@Override
		public boolean isState() {
			return false;
		}
	}
	
	/** A set action.
	 * @author gaprice@lbl.gov
	 *
	 */
	public final class SetAction implements Action {
		
		private static final SetAction INSTANCE = new SetAction();
		
		private SetAction() {}

		@Override
		public boolean isRemove() {
			return false;
		}

		@Override
		public boolean isNoAction() {
			return false;
		}

		@Override
		public boolean isSet() {
			return true;
		}

		@Override
		public boolean isState() {
			return false;
		}
	}
	
	/** An action that represents that no action is required.
	 * @author gaprice@lbl.gov
	 *
	 */
	public final class NoAction implements Action {
		
		private static final NoAction INSTANCE = new NoAction();

		private NoAction() {}

		@Override
		public boolean isRemove() {
			return false;
		}

		@Override
		public boolean isNoAction() {
			return true;
		}

		@Override
		public boolean isSet() {
			return false;
		}

		@Override
		public boolean isState() {
			return false;
		}
	}
}


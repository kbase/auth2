package us.kbase.auth2.lib.config;

/** An action to take with relation to a configuration item.
 * @author gaprice@lbl.gov
 *
 */
public abstract class ConfigAction {
	
	private ConfigAction() {}
	
	//TODO NOW TEST

	/** Returns true if this ConfigAction simply represents the state of the configuration item.
	 * 
	 * No action is required, but a value for the configuration item may be expected.
	 * @return true if the action is actually a state.
	 */
	public abstract boolean isState();
	
	/** Returns true if no action is required.
	 * @return true if no action is required.
	 */
	public abstract boolean isNoAction();
	
	/** Returns true if this ConfigAction represents a set action - the configuration item should
	 * be set to a new value.
	 * @return true if this action is a set.
	 */
	public abstract boolean isSet();
	
	/** Returns true if this ConfigAction represents a remove action - the configuration item
	 * should be removed from the configuration.
	 * @return true if this action is a remove.
	 */
	public abstract boolean isRemove();
	
	static State state() {
		return State.INSTANCE;
	}
	
	static Action remove() {
		return RemoveAction.INSTANCE;
	}
	
	static Action noAction() {
		return NoAction.INSTANCE;
	}
	
	static Action set() {
		return SetAction.INSTANCE;
	}
	
	/** A configuration state. 
	 * @author gaprice@lbl.gov
	 *
	 */
	public static final class State extends ConfigAction {
		
		private static final State INSTANCE = new State();
		
		private State() {}
		
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
	public static abstract class Action extends ConfigAction {
		
		private Action() {}
	}
	
	private static final class RemoveAction extends Action {
		
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
	
	private static final class SetAction extends Action {
		
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
	
	private static final class NoAction extends Action {
		
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


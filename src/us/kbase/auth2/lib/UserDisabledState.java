package us.kbase.auth2.lib;

import java.util.Date;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** The disabled state of a user account. Can represent the state for a user account that 1) has
 * never been disabled, 2) is currently disabled, or 3) has been reenabled.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class UserDisabledState {
	
	private static final int MAX_DISABLED_REASON_LENGTH = 1000;
	private final String disabledReason;
	private final UserName byAdmin;
	private final Long time;
	
	/** Create a state object for a user that is in the disabled state.
	 * @param disabledReason the reason the user was disabled.
	 * @param byAdmin the administrator that disabled the user.
	 * @param time the time at which the user was disabled.
	 * @throws IllegalParameterException if disabledReason is too long.
	 * @throws MissingParameterException if disabledReason is missing.
	 */
	public UserDisabledState(
			final String disabledReason,
			final UserName byAdmin,
			final Date time)
			throws IllegalParameterException, MissingParameterException {
		super();
		Utils.checkString(disabledReason, "Disabled reason", MAX_DISABLED_REASON_LENGTH);
		if (byAdmin == null) {
			throw new NullPointerException("byAdmin");
		}
		if (time == null) {
			throw new NullPointerException("time");
		}
		this.disabledReason = disabledReason.trim();
		this.byAdmin = byAdmin;
		this.time = time.getTime();
	}
	
	/** Create a state object for a user that has been disabled at least once, but has been
	 * re-enabled.
	 * @param byAdmin the administrator that enabled the user.
	 * @param time the time at which the user was enabled.
	 */
	public UserDisabledState(final UserName byAdmin, final Date time) {
		if (byAdmin == null) {
			throw new NullPointerException("byAdmin");
		}
		if (time == null) {
			throw new NullPointerException("time");
		}
		this.disabledReason = null;
		this.byAdmin = byAdmin;
		this.time = time.getTime();
	}
	
	/** Create a state object for a user that has never been disabled. */
	public UserDisabledState() {
		disabledReason = null;
		byAdmin = null;
		time = null;
	}
	
	/** Whether the user is disabled.
	 * @return true if the user is disabled, false otherwise.
	 */
	public boolean isDisabled() {
		return disabledReason != null;
	}

	/** Get the reason the user was disabled.
	 * @return the reason the user was disabled.
	 */
	public String getDisabledReason() {
		return disabledReason;
	}

	/** Get the name of the adminstrator that en/disabled the user. 
	 * @return the name of the administrator.
	 */
	public UserName getByAdmin() {
		return byAdmin;
	}

	/** Get the time the user was en/disabled.
	 * @return the time of en/disablementation.
	 */
	public Date getTime() {
		return time == null ? null : new Date(time);
	}
	
	/** Create the appropriate disabled state object for a set of inputs.
	 * @param disabledReason the reason the user was disabled - can be null.
	 * @param byAdmin the administrator that disabled the user - can be null.
	 * @param time the time at which the user was disabled - can be null.
	 * @return the new disabled state object.
	 * @throws IllegalStateException if the inputs do not correspond to one of the 3 possible
	 * state permutations (e.g. one of the 3 constructors).
	 * @throws IllegalParameterException if disabledReason is too long. 
	 * @throws MissingParameterException if disabledReason is the empty string and byAdmin and time
	 * are supplied.
	 */
	public static UserDisabledState create(
			final String disabledReason,
			final UserName byAdmin,
			final Date time)
			throws IllegalParameterException, MissingParameterException {
		if (disabledReason == null) {
			if (byAdmin == null) {
				if (time != null) {
					throw new IllegalStateException("If byAdmin is null time must also be null");
				}
				return new UserDisabledState();
			} else {
				if (time == null) {
					throw new IllegalStateException("If byAdmin is not null time cannot be null");
				}
				return new UserDisabledState(byAdmin, time);
			}
		} else {
			if (byAdmin == null || time == null) {
				throw new IllegalStateException(
						"If disabledReason is not null byAdmin and time cannot be null");
			}
			return new UserDisabledState(disabledReason, byAdmin, time);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((byAdmin == null) ? 0 : byAdmin.hashCode());
		result = prime * result + ((disabledReason == null) ? 0 : disabledReason.hashCode());
		result = prime * result + ((time == null) ? 0 : time.hashCode());
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
		UserDisabledState other = (UserDisabledState) obj;
		if (byAdmin == null) {
			if (other.byAdmin != null) {
				return false;
			}
		} else if (!byAdmin.equals(other.byAdmin)) {
			return false;
		}
		if (disabledReason == null) {
			if (other.disabledReason != null) {
				return false;
			}
		} else if (!disabledReason.equals(other.disabledReason)) {
			return false;
		}
		if (time == null) {
			if (other.time != null) {
				return false;
			}
		} else if (!time.equals(other.time)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("UserDisabledState [disabledReason=");
		builder.append(disabledReason);
		builder.append(", byAdmin=");
		builder.append(byAdmin);
		builder.append(", time=");
		builder.append(time);
		builder.append("]");
		return builder.toString();
	}
}

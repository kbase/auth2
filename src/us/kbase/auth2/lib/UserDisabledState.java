package us.kbase.auth2.lib;

import java.util.Date;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;

public class UserDisabledState {
	
	//TODO JAVADOC
	//TODO TESTS

	private final String disabledReason;
	private final UserName byAdmin;
	private final Long time;
	
	public UserDisabledState(
			final String disabledReason,
			final UserName byAdmin,
			final Date time) throws IllegalParameterException {
		super();
		if (disabledReason == null || disabledReason.trim().isEmpty()) {
			throw new IllegalParameterException(
					"A reason must be provided for why this account was disabled");
		}
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
	
	public UserDisabledState() {
		disabledReason = null;
		byAdmin = null;
		time = null;
	}
	
	public boolean isDisabled() {
		return disabledReason != null;
	}

	public String getDisabledReason() {
		return disabledReason;
	}

	public UserName getByAdmin() {
		return byAdmin;
	}

	public Date getTime() {
		return time == null ? null : new Date(time);
	}
	
	public static UserDisabledState create(
			final String disabledReason,
			final UserName byAdmin,
			final Date time) {
		if (disabledReason != null && disabledReason.isEmpty()) {
			throw new IllegalStateException("disabled reason cannot be the empty string");
		}
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
			try {
				return new UserDisabledState(disabledReason, byAdmin, time);
			} catch (IllegalParameterException e) {
				throw new RuntimeException(
						"Oh my god reality is collapsing around me plz halp", e);
			}
		}
	}
}

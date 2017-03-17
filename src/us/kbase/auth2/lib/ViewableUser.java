package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.user.AuthUser;

/** A minimal view of a user. The view always includes the user and display names, and may or may
 * not include the email address (in most cases, the email address should only be included when
 * the user themself is requesting an instance of this class).
 * 
 * @author gaprice@lbl.gov
 *
 */
public class ViewableUser {

	private final UserName userName;
	private final DisplayName displayName;
	private final Optional<EmailAddress> email;
	
	/** Create a user view.
	 * @param user the user from which to create the minimal view.
	 * @param viewEmail whether the view should include the user's email address.
	 */
	public ViewableUser(final AuthUser user, final boolean viewEmail) {
		nonNull(user, "user");
		this.userName = user.getUserName();
		this.displayName = user.getDisplayName();
		if (viewEmail) {
			this.email = Optional.of(user.getEmail());
		} else {
			this.email = Optional.absent();
		}
	}

	/** Get the user's display name.
	 * @return the display name.
	 */
	public DisplayName getDisplayName() {
		return displayName;
	}

	/** Get the user's email address.
	 * @return the email address, or absent if the email address is not viewable.
	 */
	public Optional<EmailAddress> getEmail() {
		return email;
	}

	/** Get the user's user name.
	 * @return the user's user name.
	 */
	public UserName getUserName() {
		return userName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((displayName == null) ? 0 : displayName.hashCode());
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
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
		ViewableUser other = (ViewableUser) obj;
		if (displayName == null) {
			if (other.displayName != null) {
				return false;
			}
		} else if (!displayName.equals(other.displayName)) {
			return false;
		}
		if (email == null) {
			if (other.email != null) {
				return false;
			}
		} else if (!email.equals(other.email)) {
			return false;
		}
		if (userName == null) {
			if (other.userName != null) {
				return false;
			}
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}
	
}

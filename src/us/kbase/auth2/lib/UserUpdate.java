package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import com.google.common.base.Optional;

/** This class represents an update to a user's details as submitted by a user.
 * @author gaprice@lbl.gov
 *
 */
public class UserUpdate {
	
	private Optional<DisplayName> displayName = Optional.absent();
	private Optional<EmailAddress> email = Optional.absent();
	
	/** Create an update. */
	public UserUpdate() {}
	
	/** Set the display name to be updated.
	 * @param displayName the name to be updated.
	 * @return this UserUpdate.
	 */
	public UserUpdate withDisplayName(final DisplayName displayName) {
		nonNull(displayName, "displayName");
		this.displayName = Optional.of(displayName);
		return this;
	}
	
	/** Set the email address to be updated.
	 * @param email the email address to be updated.
	 * @return this UserUpdate.
	 */
	public UserUpdate withEmail(final EmailAddress email) {
		nonNull(email, "email");
		this.email = Optional.of(email);
		return this;
	}
	
	/** Returns the display name for the update, or absent if no update is to be performed.
	 * @return the display name.
	 */
	public Optional<DisplayName> getDisplayName() {
		return displayName;
	}

	/** Returns the email address for the update, or absent if no update is to be performed.
	 * @return the email address.
	 */
	public Optional<EmailAddress> getEmail() {
		return email;
	}
	
	/** Returns whether this update instance contains any updates to be made.
	 * @return true if there are updates to be made, false otherwise.
	 */
	public boolean hasUpdates() {
		return displayName.isPresent() || email.isPresent();
	}
}

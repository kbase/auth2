package us.kbase.auth2.lib;

/** This class represents an update to a user's details as submitted by a user.
 * @author gaprice@lbl.gov
 *
 */
public class UserUpdate {
	
	private DisplayName displayName = null;
	private EmailAddress email = null;
	
	/** Create an update. */
	public UserUpdate() {}
	
	/** Set the display name to be updated. Null indicates no update will be performed.
	 * @param displayName the name to be updated.
	 * @return this UserUpdate.
	 */
	public UserUpdate withDisplayName(final DisplayName displayName) {
		this.displayName = displayName;
		return this;
	}
	
	/** Set the email address to be updated. Null indicates no update will be performed.
	 * @param email the email address to be updated.
	 * @return this UserUpdate.
	 */
	public UserUpdate withEmail(final EmailAddress email) {
		this.email = email;
		return this;
	}
	
	/** Returns the display name for the update, or null if no update is to be performed.
	 * @return the display name.
	 */
	public DisplayName getDisplayName() {
		return displayName;
	}

	/** Returns the email address for the update, or null if no update is to be performed.
	 * @return the email address.
	 */
	public EmailAddress getEmail() {
		return email;
	}
	
	/** Returns whether this update instance contains any updates to be made.
	 * @return true if there are updates to be made, false otherwise.
	 */
	public boolean hasUpdates() {
		return displayName != null || email != null;
	}
}

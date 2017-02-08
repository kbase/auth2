package us.kbase.auth2.lib;

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
	private final EmailAddress email;
	
	/** Create a user view.
	 * @param user the user from which to create the minimal view.
	 * @param viewEmail whether the view should include the user's email address.
	 */
	public ViewableUser(final AuthUser user, final boolean viewEmail) {
		if (user == null) {
			throw new NullPointerException("user");
		}
		this.userName = user.getUserName();
		this.displayName = user.getDisplayName();
		if (viewEmail) {
			this.email = user.getEmail();
		} else {
			this.email = null;
		}
	}

	/** Get the user's display name.
	 * @return the display name.
	 */
	public DisplayName getDisplayName() {
		return displayName;
	}

	/** Get the user's email address.
	 * @return the email address, or null if the email address is not viewable.
	 */
	public EmailAddress getEmail() {
		return email;
	}

	/** Get the user's user name.
	 * @return the user's user name.
	 */
	public UserName getUserName() {
		return userName;
	}
}

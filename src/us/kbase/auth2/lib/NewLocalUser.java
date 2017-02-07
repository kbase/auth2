package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.Date;
import java.util.Set;

/** A newly created local user. See the notes for LocalUser.
 * @author gaprice@lbl.gov
 *
 */
public class NewLocalUser extends LocalUser {

	/** Create a new local user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param created the date the user account was created.
	 * @param lastLogin the date of the user's last login.
	 * @param passwordHash a salted, hashed password for the user.
	 * @param salt the salt for the hashed password. 
	 * @param forceReset whether the user is required to reset their password on the next login.
	 */
	public NewLocalUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Date created,
			final Date lastLogin,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset) {
		super(userName, email, displayName, Collections.emptySet(), created, lastLogin,
				new UserDisabledState(), passwordHash, salt, forceReset, null);
	}

	@Override
	public Set<String> getCustomRoles() {
		return Collections.emptySet();
	}

}

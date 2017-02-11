package us.kbase.auth2.lib;

import java.util.Date;

/** A newly created local user.
 * @author gaprice@lbl.gov
 *
 */
public class NewLocalUser extends LocalUser {

	/** Create a new local user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param passwordHash a salted, hashed password for the user.
	 * @param salt the salt for the hashed password. 
	 * @param forceReset whether the user is required to reset their password on the next login.
	 */
	public NewLocalUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset) {
		super(userName, email, displayName, null, null, new Date(), null,
				new UserDisabledState(), passwordHash, salt, forceReset, null);
	}
}

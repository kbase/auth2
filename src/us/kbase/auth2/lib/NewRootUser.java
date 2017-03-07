package us.kbase.auth2.lib;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

/** A newly created root user.
 * @author gaprice@lbl.gov
 *
 */
public class NewRootUser extends LocalUser {
	
	/** Create a new root user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param created the date the user was created.
	 * @param passwordHash a salted, hashed password for the user.
	 * @param salt the salt for the hashed password. 
	 */
	public NewRootUser(
			final EmailAddress email,
			final DisplayName displayName,
			final Instant created,
			final byte[] passwordHash,
			final byte[] salt) {
		super(UserName.ROOT, email, displayName, new HashSet<>(Arrays.asList(Role.ROOT)), null,
				created, null, new UserDisabledState(), passwordHash, salt, false, null);
	}
}

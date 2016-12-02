package us.kbase.auth2.service.common;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;

/* methods that are useful for the UI and API */
public class ServiceCommon {

	//TODO JAVADOC
	//TODO TEST
	
	public static IncomingToken getToken(final String token)
			throws NoTokenProvidedException {
		if (token == null || token.trim().isEmpty()) {
			throw new NoTokenProvidedException("No user token provided");
		}
		return new IncomingToken(token.trim());
	}

	public static void updateUser(
			final Authentication auth,
			final IncomingToken token,
			final String displayName,
			final String email)
			throws IllegalParameterException, InvalidTokenException, AuthStorageException {
		final DisplayName dn;
		final EmailAddress e;
		try {
			if (displayName == null || displayName.isEmpty()) {
				dn = null;
			} else {
				dn = new DisplayName(displayName);
			}
			if (email == null || email.isEmpty()) {
				e = null;
			} else {
				e = new EmailAddress(email);
			}
		} catch (MissingParameterException mpe) {
			throw new RuntimeException("This is impossible", mpe);
		}
		final UserUpdate uu = new UserUpdate().withEmail(e).withDisplayName(dn);
		auth.updateUser(token, uu);
	}

}

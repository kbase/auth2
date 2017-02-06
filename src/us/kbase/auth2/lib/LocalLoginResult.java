package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.NewToken;

/** Represents the result of a successful local login, which can result of one of two states:
 * 
 * 1) The login is complete and a new token returned.
 * 2) A password reset is required.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class LocalLoginResult {

	private final UserName userName;
	private final NewToken token;
	
	/** Create a login result where a password reset is required.
	 * @param userName the username of the user that logged in.
	 */
	public LocalLoginResult(final UserName userName) {
		if (userName == null) {
			throw new NullPointerException("userName");
		}
		this.userName = userName;
		token = null;
	}
	
	/** Create a login result where the login is complete.
	 * @param token the user's new token.
	 */
	public LocalLoginResult(final NewToken token) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		userName = null;
		this.token = token;
	}

	/** Returns whether a password reset is required.
	 * @return true if a password reset is required, false otherwise.
	 */
	public boolean isPwdResetRequired() {
		return token == null;
	}

	/** Get the user's new token.
	 * @return the token.
	 * @throws IllegalStateException if a password reset is required.
	 */
	public NewToken getToken() {
		if (token == null) {
			throw new IllegalStateException("no token");
		}
		return token;
	}
	
	/** Get the name of the user requiring a password reset.
	 * @return the username.
	 * @throws IllegalStateException if a password reset is not required.
	 */
	public UserName getUserName() {
		if (userName == null) {
			throw new IllegalStateException("no username");
		}
		return userName;
	}
}

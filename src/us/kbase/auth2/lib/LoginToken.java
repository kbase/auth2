package us.kbase.auth2.lib;

import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;

/** A token provided as part of the login process. One of two possible tokens will be provided:
 * 
 * 1) A login token, indicating that the login process is complete.
 * 2) A temporary token, indicating that there are more steps to be completed in the login process.
 * The temporary token is associated with the state of the login process in the authorization
 * storage system.
 * 
 * The state of the login process is also included.
 * @author gaprice@lbl.gov
 *
 */
public class LoginToken {
	
	private final NewToken token;
	private final TemporaryToken temporaryToken;
	private final LoginState ls;
	
	/** Create a LoginToken with a temporary token, indicating that the login process is
	 * incomplete.
	 * @param token the temporary token.
	 * @param loginState the current login state.
	 */
	public LoginToken(final TemporaryToken token, final LoginState loginState) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		if (loginState == null) {
			throw new NullPointerException("loginState");
		}
		this.temporaryToken = token;
		this.token = null;
		this.ls = loginState;
	}
	
	/** Create a LoginToken with a new token, indicating the login process is complete.
	 * @param token the new token
	 * @param loginState the current login state.
	 */
	public LoginToken(final NewToken token, final LoginState loginState) {
		if (token == null) {
			throw new NullPointerException("token");
		}
		if (loginState == null) {
			throw new NullPointerException("loginState");
		}
		this.temporaryToken = null;
		this.token = token;
		this.ls = loginState;
		if (loginState.getUsers().size() != 1 || !loginState.getIdentities().isEmpty()) {
			throw new IllegalStateException(
					"Login process is complete but user count != 1 or unlinked identities > 0");
		}
	}

	/** Returns true if the login process is complete, false otherwise.
	 * @return true if the login process is complete.
	 */
	public boolean isLoggedIn() {
		return token != null;
	}
	
	/** Get the new token for a logged in user.
	 * @return the new token, or null if the user is not logged in.
	 */
	public NewToken getToken() {
		return token;
	}
	
	/** Get the temporary token for a user for which the login process is incomplete.
	 * @return the temporary token, or null if the user is logged in.
	 */
	public TemporaryToken getTemporaryToken() {
		return temporaryToken;
	}
	
	/** Gets the state of the login process. If the login is complete, the login state will
	 * contain one user and no unlinked identities.
	 * @return the login state.
	 */
	public LoginState getLoginState() {
		return ls;
	}
}

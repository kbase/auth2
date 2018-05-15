package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import com.google.common.base.Optional;

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
	
	private final Optional<NewToken> token;
	private final Optional<TemporaryToken> temporaryToken;
	
	/** Create a LoginToken with a temporary token, indicating that the login process is
	 * incomplete.
	 * @param token the temporary token.
	 */
	public LoginToken(final TemporaryToken token) {
		nonNull(token, "token");
		this.temporaryToken = Optional.of(token);
		this.token = Optional.absent();
	}
	
	/** Create a LoginToken with a new token, indicating the login process is complete.
	 * @param token the new token.
	 */
	public LoginToken(final NewToken token) {
		nonNull(token, "token");
		this.temporaryToken = Optional.absent();
		this.token = Optional.of(token);
	}

	/** Returns true if the login process is complete, false otherwise.
	 * @return true if the login process is complete.
	 */
	public boolean isLoggedIn() {
		return token.isPresent();
	}
	
	/** Get the new token for a logged in user.
	 * @return the new token, or absent if the user is not logged in.
	 */
	public Optional<NewToken> getToken() {
		return token;
	}
	
	/** Get the temporary token for a user for which the login process is incomplete.
	 * @return the temporary token, or absent if the user is logged in.
	 */
	public Optional<TemporaryToken> getTemporaryToken() {
		return temporaryToken;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((temporaryToken == null) ? 0 : temporaryToken.hashCode());
		result = prime * result + ((token == null) ? 0 : token.hashCode());
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
		LoginToken other = (LoginToken) obj;
		if (temporaryToken == null) {
			if (other.temporaryToken != null) {
				return false;
			}
		} else if (!temporaryToken.equals(other.temporaryToken)) {
			return false;
		}
		if (token == null) {
			if (other.token != null) {
				return false;
			}
		} else if (!token.equals(other.token)) {
			return false;
		}
		return true;
	}
}

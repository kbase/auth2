package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;

import java.net.URI;

import us.kbase.auth2.lib.token.TemporaryToken;

/** Contains information necessary for initiating an OAuth2 flow with a 3rd party provider,
 * primarily the redirect URL and a temporary token to track the user through the flow.
 *
 */
public class OAuth2StartData {
	
	private final URI redirectURI;
	private final TemporaryToken tempToken;
	private final String state;  // TODO NOW OAUTH remove, store state in DB vs cookie
	
	private OAuth2StartData(
			final URI redirectURI,
			final TemporaryToken temporaryToken,
			final String state) {
		this.redirectURI = requireNonNull(redirectURI, "redirectURI");
		this.tempToken = requireNonNull(temporaryToken, "temporaryToken");
		this.state = state; // since this will be removed shortly we don't bother with checks
	}
	
	/** Create the OAuth data.
	 * @param redirectURI the 3rd party redirect URI.
	 * @param tempToken the temporary token to provide to the user to track them through the flow.
	 * @param state the OAuth2 state variable.
	 */
	public static OAuth2StartData build(
			final URI redirectURI,
			final TemporaryToken tempToken,
			final String state) {
		return new OAuth2StartData(redirectURI, tempToken, state);
	}

	/** Get the 3rd party redirect URI.
	 * @return the URI.
	 */
	public URI getRedirectURI() {
		return redirectURI;
	}

	/** Get the temporary token for tracking the OAuth2 flow.
	 * @return the temporary token.
	 */
	public TemporaryToken getTemporaryToken() {
		return tempToken;
	}

	/** Get the OAuth2 state variable.
	 * @return the state variable.
	 */
	public String getState() {
		return state;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((redirectURI == null) ? 0 : redirectURI.hashCode());
		result = prime * result + ((state == null) ? 0 : state.hashCode());
		result = prime * result + ((tempToken == null) ? 0 : tempToken.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		OAuth2StartData other = (OAuth2StartData) obj;
		if (redirectURI == null) {
			if (other.redirectURI != null)
				return false;
		} else if (!redirectURI.equals(other.redirectURI))
			return false;
		if (state == null) {
			if (other.state != null)
				return false;
		} else if (!state.equals(other.state))
			return false;
		if (tempToken == null) {
			if (other.tempToken != null)
				return false;
		} else if (!tempToken.equals(other.tempToken))
			return false;
		return true;
	}
}

package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.Objects;

import us.kbase.auth2.lib.token.TemporaryToken;

/** Contains information necessary for initiating an OAuth2 flow with a 3rd party provider,
 * primarily the redirect URL and a temporary token to track the user through the flow.
 *
 */
public class OAuth2StartData {
	
	private final URI redirectURI;
	private final TemporaryToken tempToken;
	
	private OAuth2StartData(final URI redirectURI, final TemporaryToken temporaryToken) {
		this.redirectURI = requireNonNull(redirectURI, "redirectURI");
		this.tempToken = requireNonNull(temporaryToken, "temporaryToken");
	}
	
	/** Create the OAuth data.
	 * @param redirectURI the 3rd party redirect URI.
	 * @param tempToken the temporary token to provide to the user to track them through the flow.
	 * @return the OAuth2 data.
	 */
	public static OAuth2StartData build(final URI redirectURI, final TemporaryToken tempToken) {
		return new OAuth2StartData(redirectURI, tempToken);
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

	@Override
	public int hashCode() {
		return Objects.hash(redirectURI, tempToken);
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
		OAuth2StartData other = (OAuth2StartData) obj;
		return Objects.equals(redirectURI, other.redirectURI) && Objects.equals(tempToken, other.tempToken);
	}
}

package us.kbase.auth2.service;

/* for configuration items that need to be accessible to the API classes but need not be
 * stored in the db
 */
public class AuthAPIStaticConfig {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final String cookieName;

	public AuthAPIStaticConfig(final String tokenCookieName) {
		if (tokenCookieName == null || tokenCookieName.trim().isEmpty()) {
			throw new IllegalArgumentException("tokenCookieName cannot be null or empty");
		}
		this.cookieName = tokenCookieName;
	}

	public String getTokenCookieName() {
		return cookieName;
	}
}

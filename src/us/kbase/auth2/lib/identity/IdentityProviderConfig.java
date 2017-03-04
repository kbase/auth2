package us.kbase.auth2.lib.identity;

import java.net.URISyntaxException;
import java.net.URL;

/** A configuration for an identity provider.
 * @author gaprice@lbl.gov
 *
 * @see IdentityProvider
 * @see IdentityProviderFactory
 */
public class IdentityProviderConfig {
	
	private final String identityProviderFactoryClass;
	private final String clientID;
	private final String clientSecret;
	private final URL loginURL;
	private final URL apiURL;
	private final URL loginRedirectURL;
	private final URL linkRedirectURL;
	
	/** Create a configuration for an identity provider.
	 * @param identityProviderFactoryClass the class name of the identity provider factory for this
	 * configuration.
	 * @param loginURL the login url for the identity provider; where users should be redirected.
	 * @param apiURL the api url for the identity provider; where server to server requests should
	 * be directed.
	 * @param clientID the client ID for the identity provider.
	 * @param clientSecret the client secret for the identity provider.
	 * @param loginRedirectURL the url to which the provider should redirect in the process of a
	 * login.
	 * @param linkRedirectURL the url to which the provider should redirect in the process of
	 * linking accounts.
	 * @throws IdentityProviderConfigurationException if any of the inputs were unacceptable.
	 */
	public IdentityProviderConfig(
			final String identityProviderFactoryClass,
			final URL loginURL,
			final URL apiURL,
			final String clientID,
			final String clientSecret,
			final URL loginRedirectURL,
			final URL linkRedirectURL)
			throws IdentityProviderConfigurationException {
		notNullOrEmpty(identityProviderFactoryClass, "Identity provider name");
		notNullOrEmpty(clientID, "Client ID for " + identityProviderFactoryClass +
				" identity provider");
		notNullOrEmpty(clientSecret, "Client secret for " + identityProviderFactoryClass + 
				" identity provider");
		this.identityProviderFactoryClass = identityProviderFactoryClass.trim();
		this.clientID = clientID.trim();
		this.clientSecret = clientSecret.trim();
		this.loginURL = loginURL;
		this.apiURL = apiURL;
		this.loginRedirectURL = loginRedirectURL;
		this.linkRedirectURL = linkRedirectURL;

		checkValidURI(this.loginURL, "Login URL");
		checkValidURI(this.apiURL, "API URL");
		checkValidURI(this.loginRedirectURL, "Login redirect URL");
		checkValidURI(this.linkRedirectURL, "Link redirect URL");
	}

	private void checkValidURI(final URL url, final String name)
			throws IdentityProviderConfigurationException {
		if (url == null) {
			throw new IdentityProviderConfigurationException(String.format(
					"%s for %s identity provider cannot be null", name,
					identityProviderFactoryClass));
		}
		try {
			url.toURI();
		} catch (URISyntaxException e) {
			throw new IdentityProviderConfigurationException(String.format(
					"%s %s for %s identity provider is not a valid URI: %s",
					name, url, identityProviderFactoryClass, e.getMessage()), e);
		}
	}
	
	private void notNullOrEmpty(final String s, final String name)
			throws IdentityProviderConfigurationException {
		if (s == null || s.trim().isEmpty()) {
			throw new IdentityProviderConfigurationException(name + " cannot be null or empty");
		}
	}

	/** Get the class name of the identity provider factory for this configuration.
	 * @return the identity provider name.
	 */
	public String getIdentityProviderFactoryClassName() {
		return identityProviderFactoryClass;
	}

	/** Get the login url to which users should be redirected.
	 * @return the login url.
	 */
	public URL getLoginURL() {
		return loginURL;
	}
	
	/** Get the API url for server to server requests.
	 * @return the API url.
	 */
	public URL getApiURL() {
		return apiURL;
	}

	/** Get the client ID for the account used to interact with the identity provider.
	 * @return the client ID.
	 */
	public String getClientID() {
		return clientID;
	}

	/** Get the client secret for the account used to interact with the identity provider.
	 * @return the client secret.
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	/** Get the URL to which the identity provider should redirect when a login is in process.
	 * @return the login redirect url.
	 */
	public URL getLoginRedirectURL() {
		return loginRedirectURL;
	}
	
	/** Get the URL to which the identity provider should redirect when an account link is in
	 * process.
	 * @return the link url.
	 */
	public URL getLinkRedirectURL() {
		return linkRedirectURL;
	}
	
	/** Thrown when the creating an identity provider configuration fails due to bad input.
	 * @author gaprice@lbl.gov
	 *
	 */
	@SuppressWarnings("serial")
	public static class IdentityProviderConfigurationException extends Exception {
		
		public IdentityProviderConfigurationException(final String message) {
			super(message);
		}
		
		public IdentityProviderConfigurationException(
				final String message,
				final Throwable cause) {
			super(message, cause);
		}
	}
}

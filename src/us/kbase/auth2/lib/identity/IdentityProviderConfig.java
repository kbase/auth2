package us.kbase.auth2.lib.identity;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
	private final Map<String, String> customConfig;
	
	// a builder would be nice, but there's only 1 optional item...
	
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
	 * @param customConfig any custom configuration to be provided to the identity provider.
	 * @throws IdentityProviderConfigurationException if any of the inputs were unacceptable.
	 */
	public IdentityProviderConfig(
			final String identityProviderFactoryClass,
			final URL loginURL,
			final URL apiURL,
			final String clientID,
			final String clientSecret,
			final URL loginRedirectURL,
			final URL linkRedirectURL,
			final Map<String, String> customConfig)
			throws IdentityProviderConfigurationException {
		nonNull(customConfig, "customConfig");
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
		this.customConfig = Collections.unmodifiableMap(new HashMap<>(customConfig));

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
	
	/** Get any custom configuration options that have been provided for the identity provider.
	 * @return the custom configuration.
	 */
	public Map<String, String> getCustomConfiguation() {
		return customConfig;
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((apiURL == null) ? 0 : apiURL.hashCode());
		result = prime * result + ((clientID == null) ? 0 : clientID.hashCode());
		result = prime * result + ((clientSecret == null) ? 0 : clientSecret.hashCode());
		result = prime * result + ((customConfig == null) ? 0 : customConfig.hashCode());
		result = prime * result
				+ ((identityProviderFactoryClass == null) ? 0 : identityProviderFactoryClass.hashCode());
		result = prime * result + ((linkRedirectURL == null) ? 0 : linkRedirectURL.hashCode());
		result = prime * result + ((loginRedirectURL == null) ? 0 : loginRedirectURL.hashCode());
		result = prime * result + ((loginURL == null) ? 0 : loginURL.hashCode());
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
		IdentityProviderConfig other = (IdentityProviderConfig) obj;
		if (apiURL == null) {
			if (other.apiURL != null) {
				return false;
			}
		} else if (!apiURL.equals(other.apiURL)) {
			return false;
		}
		if (clientID == null) {
			if (other.clientID != null) {
				return false;
			}
		} else if (!clientID.equals(other.clientID)) {
			return false;
		}
		if (clientSecret == null) {
			if (other.clientSecret != null) {
				return false;
			}
		} else if (!clientSecret.equals(other.clientSecret)) {
			return false;
		}
		if (customConfig == null) {
			if (other.customConfig != null) {
				return false;
			}
		} else if (!customConfig.equals(other.customConfig)) {
			return false;
		}
		if (identityProviderFactoryClass == null) {
			if (other.identityProviderFactoryClass != null) {
				return false;
			}
		} else if (!identityProviderFactoryClass.equals(other.identityProviderFactoryClass)) {
			return false;
		}
		if (linkRedirectURL == null) {
			if (other.linkRedirectURL != null) {
				return false;
			}
		} else if (!linkRedirectURL.equals(other.linkRedirectURL)) {
			return false;
		}
		if (loginRedirectURL == null) {
			if (other.loginRedirectURL != null) {
				return false;
			}
		} else if (!loginRedirectURL.equals(other.loginRedirectURL)) {
			return false;
		}
		if (loginURL == null) {
			if (other.loginURL != null) {
				return false;
			}
		} else if (!loginURL.equals(other.loginURL)) {
			return false;
		}
		return true;
	}
}

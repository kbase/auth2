package us.kbase.auth2.lib.identity;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;

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
	private final URL defaultLoginRedirectURL;
	private final URL defaultLinkRedirectURL;
	private final Map<String, String> customConfig;
	private final Map<String, URL> envLoginRedirectURL;
	private final Map<String, URL> envLinkRedirectURL;
	
	private IdentityProviderConfig(
			final String identityProviderFactoryClass,
			final URL loginURL,
			final URL apiURL,
			final String clientID,
			final String clientSecret,
			final URL defaultLoginRedirectURL,
			final URL defaultLinkRedirectURL,
			final Map<String, String> customConfig,
			final Map<String, URL> envLoginRedirectURL,
			final Map<String, URL> envLinkRedirectURL) {
		this.identityProviderFactoryClass = identityProviderFactoryClass.trim();
		this.clientID = clientID.trim();
		this.clientSecret = clientSecret.trim();
		this.loginURL = loginURL;
		this.apiURL = apiURL;
		this.defaultLoginRedirectURL = defaultLoginRedirectURL;
		this.defaultLinkRedirectURL = defaultLinkRedirectURL;
		this.customConfig = Collections.unmodifiableMap(customConfig);
		this.envLoginRedirectURL = Collections.unmodifiableMap(envLoginRedirectURL);
		this.envLinkRedirectURL = Collections.unmodifiableMap(envLinkRedirectURL);
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
	
	/** Get the environments in the configuration.
	 * See {@link Builder#withEnvironment(String, URL, URL)}.
	 * @return the environements.
	 */
	public Set<String> getEnvironments() {
		return envLoginRedirectURL.keySet();
	}

	/** Get the default URL to which the identity provider should redirect when a login is in
	 * process.
	 * @return the login redirect url.
	 */
	public URL getLoginRedirectURL() {
		return defaultLoginRedirectURL;
	}
	
	/** Get the login redirect url for a specific environment.
	 * @param environment the environment name.
	 * @return the login redirect url.
	 * @throws NoSuchEnvironmentException if no such environment is configured.
	 */
	public URL getLoginRedirectURL(final String environment) throws NoSuchEnvironmentException {
		if (!envLoginRedirectURL.containsKey(environment)) {
			throw new NoSuchEnvironmentException(environment);
		}
		return envLoginRedirectURL.get(environment);
	}
	
	/** Get the defalt URL to which the identity provider should redirect when an account link is
	 * in process.
	 * @return the link url.
	 */
	public URL getLinkRedirectURL() {
		return defaultLinkRedirectURL;
	}
	
	/** Get the link redirect url for a specific environment.
	 * @param environment the environment name.
	 * @return the link redirect url.
	 * @throws NoSuchEnvironmentException if no such environment is configured.
	 */
	public URL getLinkRedirectURL(final String environment) throws NoSuchEnvironmentException {
		if (!envLoginRedirectURL.containsKey(environment)) {
			throw new NoSuchEnvironmentException(environment);
		}
		return envLinkRedirectURL.get(environment);
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
		result = prime * result + ((defaultLinkRedirectURL == null) ? 0 : defaultLinkRedirectURL.hashCode());
		result = prime * result + ((defaultLoginRedirectURL == null) ? 0 : defaultLoginRedirectURL.hashCode());
		result = prime * result + ((envLinkRedirectURL == null) ? 0 : envLinkRedirectURL.hashCode());
		result = prime * result + ((envLoginRedirectURL == null) ? 0 : envLoginRedirectURL.hashCode());
		result = prime * result
				+ ((identityProviderFactoryClass == null) ? 0 : identityProviderFactoryClass.hashCode());
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
		if (defaultLinkRedirectURL == null) {
			if (other.defaultLinkRedirectURL != null) {
				return false;
			}
		} else if (!defaultLinkRedirectURL.equals(other.defaultLinkRedirectURL)) {
			return false;
		}
		if (defaultLoginRedirectURL == null) {
			if (other.defaultLoginRedirectURL != null) {
				return false;
			}
		} else if (!defaultLoginRedirectURL.equals(other.defaultLoginRedirectURL)) {
			return false;
		}
		if (envLinkRedirectURL == null) {
			if (other.envLinkRedirectURL != null) {
				return false;
			}
		} else if (!envLinkRedirectURL.equals(other.envLinkRedirectURL)) {
			return false;
		}
		if (envLoginRedirectURL == null) {
			if (other.envLoginRedirectURL != null) {
				return false;
			}
		} else if (!envLoginRedirectURL.equals(other.envLoginRedirectURL)) {
			return false;
		}
		if (identityProviderFactoryClass == null) {
			if (other.identityProviderFactoryClass != null) {
				return false;
			}
		} else if (!identityProviderFactoryClass.equals(other.identityProviderFactoryClass)) {
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
	
	// may want to separate these into stages so we don't have a 7 item method sig. Later.
	/** Get a builder for the configuration.
	 * @param identityProviderFactoryClass the class name of the identity provider factory for this
	 * configuration.
	 * @param loginURL the login url for the identity provider; where users should be redirected.
	 * @param apiURL the api url for the identity provider; where server to server requests should
	 * be directed.
	 * @param clientID the client ID for the identity provider.
	 * @param clientSecret the client secret for the identity provider.
	 * @param defaultLoginRedirectURL the default url to which the provider should redirect in the
	 * process of a login.
	 * @param defaultLinkRedirectURL the default url to which the provider should redirect in the
	 * process of linking accounts.
	 * @return the builder.
	 * @throws IdentityProviderConfigurationException if any of the inputs were unacceptable.
	 */
	public static Builder getBuilder(
			final String identityProviderFactoryClass,
			final URL loginURL,
			final URL apiURL,
			final String clientID,
			final String clientSecret,
			final URL defaultLoginRedirectURL,
			final URL defaultLinkRedirectURL)
			throws IdentityProviderConfigurationException {
		return new Builder(
				identityProviderFactoryClass,
				loginURL,
				apiURL,
				clientID,
				clientSecret,
				defaultLoginRedirectURL,
				defaultLinkRedirectURL);
	}
	
	/** A builder for a {@link IdentityProviderConfig}.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {

		private final String identityProviderFactoryClass;
		private final String clientID;
		private final String clientSecret;
		private final URL loginURL;
		private final URL apiURL;
		private final URL defaultLoginRedirectURL;
		private final URL defaultLinkRedirectURL;
		private final Map<String, String> customConfig = new HashMap<>();
		private final Map<String, URL> envLoginRedirectURL = new HashMap<>();
		private final Map<String, URL> envLinkRedirectURL = new HashMap<>();

		private Builder(
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
			this.defaultLoginRedirectURL = loginRedirectURL;
			this.defaultLinkRedirectURL = linkRedirectURL;

			checkValidURI(this.loginURL, "Login URL");
			checkValidURI(this.apiURL, "API URL");
			checkValidURI(this.defaultLoginRedirectURL, "Login redirect URL");
			checkValidURI(this.defaultLinkRedirectURL, "Link redirect URL");
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
				throw new IdentityProviderConfigurationException(
						name + " cannot be null or empty");
			}
		}
		
		/** Add a custom configuration item to the configuration.
		 * @param key the configuration key. May not be null or whitespace only.
		 * @param value the configuration value.
		 * @return this builder.
		 * @throws IdentityProviderConfigurationException if the key is null or whitespace only.
		 */
		public Builder withCustomConfiguration(final String key, final String value)
				throws IdentityProviderConfigurationException {
			notNullOrEmpty(key, "Custom configuration key for " + identityProviderFactoryClass +
					" identity provider");
			customConfig.put(key, value);
			return this;
		}
		
		/** Add an alternate environment to the configuration. An alternate environment allows
		 * specifying a different set of redirect urls than the default so an identity provider
		 * (e.g. Google) can be directed to redirect to the correct environment.
		 * @param envName the name of the environment.
		 * @param loginRedirectURL the login redirect url.
		 * @param linkRedirectURL the link redirect url.
		 * @return this builder.
		 * @throws IdentityProviderConfigurationException if any of the arguments are invalid.
		 */
		public Builder withEnvironment(
				final String envName,
				final URL loginRedirectURL,
				final URL linkRedirectURL)
				throws IdentityProviderConfigurationException {
			notNullOrEmpty(envName, "Environment name for " + identityProviderFactoryClass +
					" identity provider");
			checkValidURI(loginRedirectURL, "Login redirect URL for environment " + envName);
			checkValidURI(linkRedirectURL, "Link redirect URL for environment " + envName);
			envLoginRedirectURL.put(envName, loginRedirectURL);
			envLinkRedirectURL.put(envName, linkRedirectURL);
			return this;
		}
		
		/** Build the configuration.
		 * @return the configuration.
		 */
		public IdentityProviderConfig build() {
			return new IdentityProviderConfig(
					identityProviderFactoryClass,
					loginURL,
					apiURL,
					clientID,
					clientSecret,
					defaultLoginRedirectURL,
					defaultLinkRedirectURL,
					customConfig,
					envLoginRedirectURL,
					envLinkRedirectURL);
		}

	}
}

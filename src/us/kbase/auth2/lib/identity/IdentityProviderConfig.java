package us.kbase.auth2.lib.identity;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class IdentityProviderConfig {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final String identityProviderName;
	private final String clientID;
	private final String clientSecrect;
	private final URI imageURI;
	private final URL loginURL;
	private final URL apiURL;
	private final URL loginRedirectURL;
	private final URL linkRedirectURL;
	
	public IdentityProviderConfig(
			final String identityProviderName,
			final URL loginURL,
			final URL apiURL,
			final String clientID,
			final String clientSecrect,
			final URI imgURI,
			final URL loginRedirectURL,
			final URL linkRedirectURL) {
		super();
		//TODO INPUT check for nulls & empty strings
		this.identityProviderName = identityProviderName.trim();
		this.clientID = clientID.trim();
		this.clientSecrect = clientSecrect.trim();
		this.imageURI = imgURI;
		this.loginURL = loginURL;
		this.apiURL = apiURL;
		this.loginRedirectURL = loginRedirectURL;
		this.linkRedirectURL = linkRedirectURL;

		checkValidURI(this.loginURL, "Login url");
		checkValidURI(this.apiURL, "API url");
		checkValidURI(this.loginRedirectURL, "Login redirect url");
		checkValidURI(this.linkRedirectURL, "Link redirect url");
	}

	private void checkValidURI(final URL url, final String name) {
		//TODO TEST ^ is ok in a url, but not in a URI
		try {
			url.toURI();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(String.format(
					"%s %s for %s identity provider is not a valid URI: %s",
					name, url, identityProviderName, e.getMessage()), e);
		}
	}

	public String getIdentityProviderName() {
		return identityProviderName;
	}

	public URL getLoginURL() {
		return loginURL;
	}
	
	public URL getApiURL() {
		return apiURL;
	}

	public String getClientID() {
		return clientID;
	}

	public String getClientSecrect() {
		return clientSecrect;
	}

	public URI getImageURI() {
		return imageURI;
	}

	public URL getLoginRedirectURL() {
		return loginRedirectURL;
	}
	
	public URL getLinkRedirectURL() {
		return linkRedirectURL;
	}
}

package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.URL;

import org.junit.Test;

import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;

public class IdentityProviderConfigTest {

	@Test
	public void goodInput() throws Exception {
		final IdentityProviderConfig c = new IdentityProviderConfig(
				"MyProv",
				new URL("http://login.com"),
				new URL("http://api.com"),
				"foo",
				"bar",
				new URL("https://loginredirect.com"),
				new URL("https://linkredirect.com"));
		assertThat("incorrect api URL", c.getApiURL(), is(new URL("http://api.com")));
		assertThat("incorrect client id", c.getClientID(), is("foo"));
		assertThat("incorrect client secret", c.getClientSecret(), is("bar"));
		assertThat("incorrect provider name", c.getIdentityProviderName(), is("MyProv"));
		assertThat("incorrect link redirect URL", c.getLinkRedirectURL(),
				is(new URL("https://linkredirect.com")));
		assertThat("incorrect login redirect URL", c.getLoginRedirectURL(),
				is(new URL("https://loginredirect.com")));
		assertThat("incorrect login URL", c.getLoginURL(), is(new URL("http://login.com")));
	}
	
	@Test
	public void badInput() throws Exception {
		final String name = "MyProv";
		final URL login = new URL("http://login.com");
		final URL api = new URL("http://api.com");
		final String clientID = "foo";
		final String clientSecret = "bar";
		final URL loginRedirect = new URL("https://loginredirect.com");
		final URL linkRedirect = new URL("https://linkredirect.com");
		
		final String exp = " for " + name + " identity provider cannot be null";
		final String strexp = exp + " or empty";
		
		// id provider name
		failCreateConfig(null, login, api, clientID, clientSecret, loginRedirect,
				linkRedirect, "Identity provider name cannot be null or empty");
		failCreateConfig("\t", login, api, clientID, clientSecret, loginRedirect,
				linkRedirect, "Identity provider name cannot be null or empty");
		
		//login url
		failCreateConfig(name, null, api, clientID, clientSecret, loginRedirect,
				linkRedirect, "Login URL" + exp);
		failCreateConfig(name, new URL("http://login^foo.com"), api, clientID, clientSecret,
				loginRedirect, linkRedirect,
				"Login URL http://login^foo.com for MyProv identity provider is not a valid " +
				"URI: Illegal character in authority at index 7: http://login^foo.com");
		
		//api url
		failCreateConfig(name, login, null, clientID, clientSecret, loginRedirect,
				linkRedirect, "API URL" + exp);
		failCreateConfig(name, login, new URL("http://api^fo.com"), clientID, clientSecret,
				loginRedirect, linkRedirect,
				"API URL http://api^fo.com for MyProv identity provider is not a valid " +
				"URI: Illegal character in authority at index 7: http://api^fo.com");
				// not sure why the index is the same as the login url
		
		//client ID
		failCreateConfig(name, login, api, null, clientSecret, loginRedirect,
				linkRedirect, "Client ID" + strexp);
		failCreateConfig(name, login, api, "", clientSecret, loginRedirect,
				linkRedirect, "Client ID" + strexp);
		
		//client secret
		failCreateConfig(name, login, api, clientID, null, loginRedirect,
				linkRedirect, "Client secret" + strexp);
		failCreateConfig(name, login, api, clientID, " ", loginRedirect,
				linkRedirect, "Client secret" + strexp);
		
		//login redirect
		failCreateConfig(name, login, api, clientID, clientSecret, null,
				linkRedirect, "Login redirect URL" + exp);
		failCreateConfig(name, login, api, clientID, clientSecret,
				new URL("http://lr^f.com"), linkRedirect,
				"Login redirect URL http://lr^f.com for MyProv identity provider is not a valid " +
				"URI: Illegal character in authority at index 7: http://lr^f.com");
		
		//link redirect
		failCreateConfig(name, login, api, clientID, clientSecret, login,
				null, "Link redirect URL" + exp);
		failCreateConfig(name, login, api, clientID, clientSecret,
				login, new URL("http://linkredir^foobar.com"),
				"Link redirect URL http://linkredir^foobar.com for MyProv identity provider is " +
				"not a valid URI: Illegal character in authority at index 7: " +
				"http://linkredir^foobar.com");
	}

	private void failCreateConfig(
			final String name,
			final URL login,
			final URL api,
			final String clientID,
			final String clientSecret,
			final URL loginRedirect,
			final URL linkRedirect,
			final String exception) {
		try {
			new IdentityProviderConfig(name, login, api, clientID, clientSecret,
					loginRedirect, linkRedirect);
			fail("created bad id provider config");
		} catch (IdentityProviderConfigurationException e) {
			assertThat("incorrect exception message", e.getMessage(), is(exception));
		}
	}
	
}

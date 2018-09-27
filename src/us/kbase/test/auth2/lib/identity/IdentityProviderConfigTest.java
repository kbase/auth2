package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.Builder;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;

public class IdentityProviderConfigTest {

	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(IdentityProviderConfig.class).usingGetClass().verify();
	}
	
	@Test
	public void goodInput() throws Exception {
		final IdentityProviderConfig c = IdentityProviderConfig.getBuilder(
				"MyProv",
				new URL("http://login.com"),
				new URL("http://api.com"),
				"foo",
				"bar",
				new URL("https://loginredirect.com"),
				new URL("https://linkredirect.com"))
				.withCustomConfiguration("foo", "bar")
				.withCustomConfiguration("baz", "bat")
				.build();
		assertThat("incorrect api URL", c.getApiURL(), is(new URL("http://api.com")));
		assertThat("incorrect client id", c.getClientID(), is("foo"));
		assertThat("incorrect client secret", c.getClientSecret(), is("bar"));
		assertThat("incorrect provider name", c.getIdentityProviderFactoryClassName(), is("MyProv"));
		assertThat("incorrect link redirect URL", c.getLinkRedirectURL(),
				is(new URL("https://linkredirect.com")));
		assertThat("incorrect login redirect URL", c.getLoginRedirectURL(),
				is(new URL("https://loginredirect.com")));
		assertThat("incorrect login URL", c.getLoginURL(), is(new URL("http://login.com")));
		assertThat("incorrect custom config", c.getCustomConfiguation(),
				is(ImmutableMap.of("foo", "bar", "baz", "bat")));
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
		
		// custom config
		final Map<String, String> cc = new HashMap<>();
		cc.put(null, "foo");
		failCreateConfig(name, login, api, clientID, clientSecret, loginRedirect,
				linkRedirect, cc, "Custom configuration key" + strexp);
		cc.clear();
		cc.put("  \t   ", "foo");
		failCreateConfig(name, login, api, clientID, clientSecret, loginRedirect,
				linkRedirect, cc, "Custom configuration key" + strexp);
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
		failCreateConfig(name, login, api, clientID, clientSecret, loginRedirect, linkRedirect,
				Collections.emptyMap(), exception);
	}
	
	private void failCreateConfig(
			final String name,
			final URL login,
			final URL api,
			final String clientID,
			final String clientSecret,
			final URL loginRedirect,
			final URL linkRedirect,
			final Map<String, String> custom,
			final String exception) {
	
		try {
			final Builder cfg = IdentityProviderConfig.getBuilder(
					name, login, api, clientID, clientSecret, loginRedirect, linkRedirect);
			for (final Entry<String, String> e: custom.entrySet()) {
				cfg.withCustomConfiguration(e.getKey(), e.getValue());
			}
			fail("created bad id provider config");
		} catch (IdentityProviderConfigurationException e) {
			assertThat("incorrect exception message", e.getMessage(), is(exception));
		}
	}
	
	@Test
	public void immutable() throws Exception {
		final IdentityProviderConfig c = IdentityProviderConfig.getBuilder(
				"MyProv",
				new URL("http://login.com"),
				new URL("http://api.com"),
				"foo",
				"bar",
				new URL("https://loginredirect.com"),
				new URL("https://linkredirect.com"))
				.withCustomConfiguration("foo", "bar")
				.withCustomConfiguration("baz", "bat")
				.build();
		
		try {
			c.getCustomConfiguation().put("foo", "bar");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
}

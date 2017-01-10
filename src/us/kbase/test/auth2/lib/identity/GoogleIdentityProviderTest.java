package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;

import com.fasterxml.jackson.databind.ObjectMapper;

import us.kbase.auth2.lib.identity.GoogleIdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.GoogleIdentityProvider.GoogleIdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.test.auth2.TestCommon;

public class GoogleIdentityProviderTest {
	
	// a lot of code in common with Globus, try to make common class at some point 

	private static final String CONTENT_TYPE = "content-type";
	private static final String ACCEPT = "accept";
	private static final String APP_JSON = "application/json";
	private static final String GOOGLE = "Google";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	private static final String STRING1000;
	private static final String STRING1001;
	static {
		final String s = "foobarbaz0";
		String r = "";
		for (int i = 0; i < 100; i++) {
			r += s;
		}
		STRING1000 = r;
		STRING1001 = r + "a";
	}
	
	private static ClientAndServer mockClientAndServer;
	
	@BeforeClass
	public static void setUpClass() {
		mockClientAndServer = ClientAndServer.startClientAndServer(TestCommon.findFreePort());
	}
	
	@After
	public void tearDownTest() {
		mockClientAndServer.reset();
	}
	
	private static final IdentityProviderConfig CFG;
	static {
		try {
			CFG = new IdentityProviderConfig(
					"Google",
					new URL("https://glogin.com"),
					new URL("https://gsetapiurl.com"),
					"gfoo",
					"gbar",
					new URI("http://gimage.com"),
					new URL("https://gloginredir.com"),
					new URL("https://glinkredir.com"));
		} catch (IdentityProviderConfigurationException | URISyntaxException |
				MalformedURLException e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
	@Test
	public void simpleOperationsWithConfigurator() throws Exception {
		final GoogleIdentityProviderConfigurator gc = new GoogleIdentityProviderConfigurator();
		assertThat("incorrect provider name", gc.getProviderName(), is("Google"));
		
		final IdentityProvider gip = gc.configure(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect image uri", gip.getImageURI(), is(new URI("http://gimage.com")));
		assertThat("incorrect login url", gip.getLoginURL("foo3", false),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo3&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURL("foo4", true),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo4&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
	}
	
	@Test
	public void simpleOperationsWithoutConfigurator() throws Exception {
		
		final IdentityProvider gip = new GoogleIdentityProvider(CFG);
		assertThat("incorrect provider name", gip.getProviderName(), is("Google"));
		assertThat("incorrect image uri", gip.getImageURI(), is(new URI("http://gimage.com")));
		assertThat("incorrect login url", gip.getLoginURL("foo5", false),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo5&redirect_uri=https%3A%2F%2Fgloginredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		assertThat("incorrect link url", gip.getLoginURL("foo6", true),
				is(new URL("https://glogin.com/o/oauth2/v2/auth?" +
						"scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplus.me+profile+email" +
						"&state=foo6&redirect_uri=https%3A%2F%2Fglinkredir.com" +
						"&response_type=code&client_id=gfoo&prompt=select_account")));
		
	}
	
	@Test
	public void createFail() throws Exception {
		failCreate(null, new NullPointerException("idc"));
		failCreate(new IdentityProviderConfig(
				"foo",
				CFG.getLoginURL(),
				CFG.getApiURL(),
				CFG.getClientID(),
				CFG.getClientSecret(),
				CFG.getImageURI(),
				CFG.getLoginRedirectURL(),
				CFG.getLinkRedirectURL()),
				new IllegalArgumentException("Bad config name: foo"));
	}
	
	private void failCreate(final IdentityProviderConfig cfg, final Exception exception) {
		try {
			new GoogleIdentityProvider(cfg);
			fail("created bad globus id provider");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void illegalAuthcode() throws Exception {
		final IdentityProvider idp = new GoogleIdentityProvider(CFG);
		failGetIdentities(idp, null, true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
		failGetIdentities(idp, "  \t  \n  ", true, new IllegalArgumentException(
				"authcode cannot be null or empty"));
	}
	
	private void failGetIdentities(
			final IdentityProvider idp,
			final String authcode,
			final boolean link,
			final Exception exception) throws Exception {
		try {
			idp.getIdentities(authcode, link);
			fail("got identities with bad setup");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	private IdentityProviderConfig getTestIDConfig()
			throws IdentityProviderConfigurationException, MalformedURLException,
			URISyntaxException {
		return new IdentityProviderConfig(
				"Gooble",
				new URL("https://glogin.com"),
				new URL("http://localhost:" + mockClientAndServer.getPort()),
				"gfoo",
				"gbar",
				new URI("http://gimage.com"),
				new URL("https://gloginredir.com"),
				new URL("https://glinkredir.com"));
	}
	
}

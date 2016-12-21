package us.kbase.test.auth2.lib.identity;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.lib.identity.IdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.IdentityProviderSet;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.test.auth2.TestCommon;

public class IdentityProviderSetTest {
	
	private static final IdentityProviderConfig CFG1;
	private static final IdentityProviderConfig CFG2;
	static {
		try {
			CFG1 = new IdentityProviderConfig(
					"Test",
					new URL("http://login.com"),
					new URL("http://api.com"),
					"foo",
					"bar",
					new URI("https://image.com"),
					new URL("http://loginre.com"),
					new URL("http://linkre.com"));
			CFG2 = new IdentityProviderConfig(
					"Test2",
					new URL("http://login2.com"),
					new URL("http://api2.com"),
					"foo2",
					"bar2",
					new URI("https://image2.com"),
					new URL("http://loginre2.com"),
					new URL("http://linkre2.com"));
		} catch (IdentityProviderConfigurationException | URISyntaxException |
				MalformedURLException e) {
			throw new RuntimeException("Fix your tests scrub", e);
		}
	}

	private static class TestProviderConfigurator implements IdentityProviderConfigurator {

		private final String name;
		private final boolean test1;
		
		public TestProviderConfigurator(final String name, final boolean test1) {
			this.name = name;
			this.test1 = test1;
		}
		
		@Override
		public IdentityProvider configure(final IdentityProviderConfig cfg) {
			if (test1) {
				return new TestProvider(cfg);
			}
			return new TestProvider2(cfg);
		}

		@Override
		public String getProviderName() {
			return name;
		}
		
	}
	
	private static class TestProvider implements IdentityProvider {

		final IdentityProviderConfig cfg;
		
		public TestProvider(final IdentityProviderConfig cfg) {
			this.cfg = cfg;
		}

		@Override
		public String getProviderName() {
			return cfg.getIdentityProviderName();
		}

		@Override
		public URI getImageURI() {
			return cfg.getImageURI();
		}

		@Override
		public URL getLoginURL(final String state, final boolean link) {
			return cfg.getLoginURL();
		}

		@Override
		public Set<RemoteIdentity> getIdentities(final String authcode, final boolean link)
				throws IdentityRetrievalException {
			return new HashSet<>(Arrays.asList(new RemoteIdentity(
					new RemoteIdentityID(cfg.getClientID(), cfg.getClientSecret()),
					new RemoteIdentityDetails(cfg.getApiURL().toString(),
							cfg.getLoginRedirectURL().toString(),
							cfg.getLinkRedirectURL().toString()))));
		}
	}
	
	private static class TestProvider2 implements IdentityProvider {

		final IdentityProviderConfig cfg;
		
		public TestProvider2(final IdentityProviderConfig cfg) {
			this.cfg = cfg;
		}

		@Override
		public String getProviderName() {
			return cfg.getIdentityProviderName();
		}

		@Override
		public URI getImageURI() {
			return cfg.getImageURI();
		}

		@Override
		public URL getLoginURL(final String state, final boolean link) {
			return cfg.getLoginURL();
		}

		@Override
		public Set<RemoteIdentity> getIdentities(final String authcode, final boolean link)
				throws IdentityRetrievalException {
			return new HashSet<>();
		}
	}
	
	@Test
	public void registerAndLock() throws Exception {
		final IdentityProviderSet ids = new IdentityProviderSet();
		IdentityProviderSet ret = ids.register(new TestProviderConfigurator("Test", true));
		assertThat("fluent interface failed", ret, is(ids));
		ret = ids.configure(CFG1);
		assertThat("fluent interface failed", ret, is(ids));
		assertThat("incorrect provider list", ids.getProviders(), is(Arrays.asList("Test")));
		assertThat("incorrect locked state", ids.isLocked(), is(false));
		final IdentityProvider idp = ids.getProvider("Test");
		assertThat("incorrect provider name", idp.getProviderName(), is("Test"));
		assertThat("incorrect image URI", idp.getImageURI(), is(new URI("https://image.com")));
		assertThat("incorrect login URL", idp.getLoginURL("foo", false),
				is(new URL("http://login.com")));
		assertThat("incorrect number of identities", idp.getIdentities("foo", false).size(),
				is(1));
		
		final RemoteIdentity ri = idp.getIdentities("foo", false).iterator().next();
		assertThat("incorrect provider", ri.getRemoteID().getProvider(), is("foo"));
		assertThat("incorrect id", ri.getRemoteID().getId(), is("bar"));
		assertThat("incorrect username", ri.getDetails().getUsername(), is("http://api.com"));
		assertThat("incorrect fullname", ri.getDetails().getFullname(), is("http://loginre.com"));
		assertThat("incorrect email", ri.getDetails().getEmail(), is("http://linkre.com"));
		
		ret = ids.lock();
		assertThat("fluent interface failed", ret, is(ids));
		assertThat("incorrect locked state", ids.isLocked(), is(true));
		ids.register(new TestProviderConfigurator("Test2", false));
		try {
			ids.configure(CFG2);
			fail("registered on locked set");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(), is("Factory is locked"));
		}
		assertThat("incorrect provider list", ids.getProviders(), is(Arrays.asList("Test")));
	}
	
	@Test
	public void multipleProviders() throws Exception {
		final IdentityProviderSet ids = new IdentityProviderSet();
		ids.register(new TestProviderConfigurator("Test2", false));
		ids.register(new TestProviderConfigurator("Test", true));
		ids.configure(CFG2);
		ids.configure(CFG1);
		
		assertThat("incorrect provider list", ids.getProviders(),
				is(Arrays.asList("Test", "Test2")));
		assertThat("incorrect locked state", ids.isLocked(), is(false));
		final IdentityProvider idp = ids.getProvider("Test");
		assertThat("incorrect provider name", idp.getProviderName(), is("Test"));
		assertThat("incorrect image URI", idp.getImageURI(), is(new URI("https://image.com")));
		assertThat("incorrect login URL", idp.getLoginURL("foo", false),
				is(new URL("http://login.com")));
		assertThat("incorrect number of identities", idp.getIdentities("foo", false).size(),
				is(1));
		
		final IdentityProvider idp2 = ids.getProvider("Test2");
		assertThat("incorrect provider name", idp2.getProviderName(), is("Test2"));
		assertThat("incorrect image URI", idp2.getImageURI(), is(new URI("https://image2.com")));
		assertThat("incorrect login URL", idp2.getLoginURL("foo", false),
				is(new URL("http://login2.com")));
		assertThat("incorrect number of identities", idp2.getIdentities("foo", false).size(),
				is(0));
	}
	
	@Test
	public void overwrite() throws Exception {
		final IdentityProviderSet ids = new IdentityProviderSet();
		ids.register(new TestProviderConfigurator("Test", true));
		ids.configure(CFG1);
		
		assertThat("incorrect provider list", ids.getProviders(), is(Arrays.asList("Test")));
		assertThat("incorrect locked state", ids.isLocked(), is(false));
		final IdentityProvider idp = ids.getProvider("Test");
		assertThat("incorrect provider name", idp.getProviderName(), is("Test"));
		assertThat("incorrect image URI", idp.getImageURI(), is(new URI("https://image.com")));
		assertThat("incorrect login URL", idp.getLoginURL("foo", false),
				is(new URL("http://login.com")));
		assertThat("incorrect number of identities", idp.getIdentities("foo", false).size(),
				is(1));
		
		ids.register(new TestProviderConfigurator("Test", false));
		ids.configure(new IdentityProviderConfig(
				"Test",
				new URL("http://login2.com"),
				new URL("http://api2.com"),
				"foo2",
				"bar2",
				new URI("https://image2.com"),
				new URL("http://loginre2.com"),
				new URL("http://linkre2.com")));
		assertThat("incorrect provider list", ids.getProviders(), is(Arrays.asList("Test")));
		assertThat("incorrect locked state", ids.isLocked(), is(false));
		final IdentityProvider idp2 = ids.getProvider("Test");
		assertThat("incorrect provider name", idp2.getProviderName(), is("Test"));
		assertThat("incorrect image URI", idp2.getImageURI(), is(new URI("https://image2.com")));
		assertThat("incorrect login URL", idp2.getLoginURL("foo", false),
				is(new URL("http://login2.com")));
		assertThat("incorrect number of identities", idp2.getIdentities("foo", false).size(),
				is(0));
	}

	@Test
	public void failRegisterConfigurator() throws Exception {
		failRegister(null, new NullPointerException("conf"));
		final IllegalArgumentException e = new IllegalArgumentException(
				"The configurator name cannot be null or empty");
		failRegister(new TestProviderConfigurator(null, false), e);
		failRegister(new TestProviderConfigurator("\t ", false), e);
	}
	
	private void failRegister(
			final IdentityProviderConfigurator cfg,
			final Exception exception) {
		final IdentityProviderSet set = new IdentityProviderSet();
		try {
			set.register(cfg);
			fail("registered bad config");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void failConfigure() throws Exception {
		final IdentityProviderSet set = new IdentityProviderSet();
		set.register(new TestProviderConfigurator("Test", true));
		failConfig(set, null, new NullPointerException("cfg"));
		failConfig(set, CFG2, new IllegalStateException(
				"Register a configurator for identity provider Test2 before attempting to " +
				"configure it"));
	}
	
	private void failConfig(
			final IdentityProviderSet ids,
			final IdentityProviderConfig cfg,
			final Exception exception) {
		try {
			ids.configure(cfg);
			fail("configured with bad config");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void failGetProvider() throws Exception {
		final IdentityProviderSet ids = new IdentityProviderSet();
		ids.register(new TestProviderConfigurator("Test", true));
		failGet(ids, null, new NoSuchIdentityProviderException("Provider name cannot be null"));
		failGet(ids, "", new NoSuchIdentityProviderException(""));
		failGet(ids, "foo", new NoSuchIdentityProviderException("foo"));
	}
	
	private void failGet(
			final IdentityProviderSet ids,
			final String provider,
			final Exception exception) {
		try {
			ids.getProvider(provider);
			fail("Got bad provider");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
}

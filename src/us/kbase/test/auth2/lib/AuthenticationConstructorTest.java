package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class AuthenticationConstructorTest {
	
	@Test
	public void construct() throws Exception {
		/* Doesn't test the default auth config. Tested in the methods that use that config. */
		final AuthStorage storage = mock(AuthStorage.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		final Authentication auth = new Authentication(storage, Collections.emptySet(),
				new TestExternalConfig("thingy"));
		verify(storage).updateConfig(new AuthConfigSet<TestExternalConfig>(ac,
				new TestExternalConfig("thingy")), false);
		
		final TestExternalConfig t = auth.getExternalConfig(new TestExternalConfigMapper());
		assertThat("incorrect external config", t, is(new TestExternalConfig("foo")));
		assertThat("incorrect providers", auth.getIdentityProviders(),
				is(Collections.emptyList()));
	}
	
	@Test
	public void updateConfigFail() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		doThrow(new AuthStorageException("foobar")).when(
				storage).updateConfig(new AuthConfigSet<TestExternalConfig>(ac,
						new TestExternalConfig("thingy")), false);
		
		failConstruct(storage, Collections.emptySet(), new TestExternalConfig("thingy"),
				new StorageInitException("Failed to set config in storage: foobar"));
	}
	
	private void failConstruct(
			final AuthStorage storage,
			final Set<IdentityProvider> ids, 
			final ExternalConfig cfg,
			final Exception e) {
		try {
			new Authentication(storage, ids, cfg);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getConfigFail() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		doThrow(new AuthStorageException("whee")).when(storage)
				.getConfig(isA(CollectingExternalConfigMapper.class));
		
		failConstruct(storage, Collections.emptySet(), new TestExternalConfig("foo"),
				new StorageInitException("Failed to initialize config manager: whee"));
	}
	
	@Test
	public void nulls() throws Exception {
		final IdentityProviderConfig cfg1 = new IdentityProviderConfig(
				"prov1", new URL("https://login1.com"), new URL("https://link1.com"),
				"cli1", "sec1", new URL("https://loginre1.com"), new URL("https://linkre1.com"));
		
		final AuthStorage storage = mock(AuthStorage.class);
		failConstruct(null, Collections.emptySet(), new TestExternalConfig("foo"),
				new NullPointerException("storage"));
		failConstruct(storage, null, new TestExternalConfig("foo"),
				new NullPointerException("identityProviderSet"));
		failConstruct(storage, set(new NullIdProv("foo", cfg1), null),
				new TestExternalConfig("foo"),
				new NullPointerException("Null identity provider in set"));
		failConstruct(storage, Collections.emptySet(), null,
				new NullPointerException("defaultExternalConfig"));
	}
	
	private static class NullIdProv implements IdentityProvider {

		private final String name;
		private final IdentityProviderConfig cfg;
		
		public NullIdProv(final String name, final IdentityProviderConfig cfg) {
			this.name = name;
			this.cfg = cfg;
		}
		
		@Override
		public String getProviderName() {
			return name;
		}

		@Override
		public URL getLoginURL(final String state, final boolean link) {
			return cfg.getLoginRedirectURL();
		}

		@Override
		public Set<RemoteIdentity> getIdentities(final String authcode, final boolean link)
				throws IdentityRetrievalException {
			return Collections.emptySet();
		}
		
	}
	
	@Test
	public void withIDs() throws Exception {
		/* Doesn't test the prov config - tested in methods that use the config */
		final AuthStorage storage = mock(AuthStorage.class);
		final IdentityProviderConfig cfg1 = new IdentityProviderConfig(
				"prov1", new URL("https://login1.com"), new URL("https://link1.com"),
				"cli1", "sec1", new URL("https://loginre1.com"), new URL("https://linkre1.com"));
		final IdentityProviderConfig cfg2 = new IdentityProviderConfig(
				"prov2", new URL("https://login2.com"), new URL("https://link2.com"),
				"cli2", "sec2", new URL("https://loginre2.com"), new URL("https://linkre2.com"));
		
		final Set<IdentityProvider> ids = new HashSet<>();
		ids.add(new NullIdProv("Prov1", cfg1));
		ids.add(new NullIdProv("Prov2", cfg2));
		
		final Map<String, ProviderConfig> idcfg = new HashMap<>();
		idcfg.put("Prov1", AuthConfig.DEFAULT_PROVIDER_CONFIG);
		idcfg.put("Prov2", AuthConfig.DEFAULT_PROVIDER_CONFIG);
		
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, idcfg,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		final Authentication auth = new Authentication(storage, ids,
				new TestExternalConfig("thingy"));
		verify(storage).updateConfig(new AuthConfigSet<TestExternalConfig>(ac,
				new TestExternalConfig("thingy")), false);
		
		assertThat("incorrect providers", auth.getIdentityProviders(),
				is(Collections.emptyList())); //since no providers are enabled
	}
	
	@Test
	public void withIDsFailDuplicate() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final IdentityProviderConfig cfg1 = new IdentityProviderConfig(
				"prov1", new URL("https://login1.com"), new URL("https://link1.com"),
				"cli1", "sec1", new URL("https://loginre1.com"), new URL("https://linkre1.com"));
		final IdentityProviderConfig cfg2 = new IdentityProviderConfig(
				"prov2", new URL("https://login2.com"), new URL("https://link2.com"),
				"cli2", "sec2", new URL("https://loginre2.com"), new URL("https://linkre2.com"));
		
		final Set<IdentityProvider> ids = new HashSet<>();
		ids.add(new NullIdProv("Prov1", cfg1));
		ids.add(new NullIdProv("Prov2", cfg2));
		ids.add(new NullIdProv("prov2", cfg2)); // should match on different case
		
		failConstruct(storage, ids, new TestExternalConfig("thing"), new IllegalArgumentException(
				"Duplicate provider name: prov2"));
	}
}

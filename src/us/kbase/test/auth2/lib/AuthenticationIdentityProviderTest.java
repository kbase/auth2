package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationIdentityProviderTest {
	
	/* Tests the identity provider related functions that are not specific to link or login. */
	
	@Test
	public void getProviders() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		final IdentityProvider idp3 = mock(IdentityProvider.class);
		final IdentityProvider idp4 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		when(idp3.getProviderName()).thenReturn("prov3");
		when(idp4.getProviderName()).thenReturn("prov4");
		
		final TestMocks testauth = initTestMocks(set(idp4, idp3, idp2, idp1));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov4", new ProviderConfig(true, true, true));
		providers.put("prov3", new ProviderConfig(true, true, true));
		providers.put("prov1", new ProviderConfig(false, true, true));
		providers.put("prov2", new ProviderConfig(true, false, false));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final List<String> provret = auth.getIdentityProviders();
		assertThat("incorrect provider list", provret,
				is(Arrays.asList("prov2", "prov3", "prov4")));
	}
	
	@Test
	public void failGetProviders() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp2, idp1));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov2", new ProviderConfig(true, false, false));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		try {
			auth.getIdentityProviders();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new RuntimeException(
					"Programming error. The configuration for the provider prov1 is no longer " +
					"accessible in the storage system"));
		}
	}
	
	@Test
	public void getURL() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);
		
		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov", new ProviderConfig(true, true, true));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getLoginURL("foobarbaz", true)).thenReturn(new URL("https://test.com"));
		
		assertThat("incorrect url", auth.getIdentityProviderURL("prov", "foobarbaz", true),
				is(new URL("https://test.com")));
		//test with alternate case
		assertThat("incorrect url", auth.getIdentityProviderURL("Prov", "foobarbaz", true),
				is(new URL("https://test.com")));
	}
	
	@Test
	public void getURLFailNulls() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);
		
		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov", new ProviderConfig(true, true, true));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failGetURL(auth, null, "foo", new NullPointerException("provider"));
		failGetURL(auth, "   \t   \n   ", "foo",
				new NoSuchIdentityProviderException("   \t   \n   "));
		failGetURL(auth, "prov", null,
				new IllegalArgumentException("state cannot be null or empty"));
		failGetURL(auth, "prov", "    \t    \n    ",
				new IllegalArgumentException("state cannot be null or empty"));
	}
	
	@Test
	public void getURLFailNoProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);
		
		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov", new ProviderConfig(true, true, true));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failGetURL(auth, "provs", "foobar", new NoSuchIdentityProviderException("provs"));
	}
	
	@Test
	public void getURLFailNotEnabled() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);
		
		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final Map<String, ProviderConfig> providers = new HashMap<>();
		providers.put("prov", new ProviderConfig(false, true, true));
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failGetURL(auth, "prov", "foobar", new NoSuchIdentityProviderException("prov"));
	}
	
	public void failGetURL(
			final Authentication auth,
			final String provider,
			final String state,
			final Exception e)
			throws Exception {
		try {
			auth.getIdentityProviderURL(provider, state, true);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	

}

package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.lib.AuthenticationTester.setupValidUserResponses;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;
import us.kbase.test.auth2.lib.AuthenticationTester.AuthOperation;
import us.kbase.test.auth2.lib.config.FailConfig.FailingMapper;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class AuthenticationConfigTest {
	
	@Test
	public void getCacheTime() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.EXT_CACHE, 70000L)),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(70000L));
	}
	
	@Test
	public void getCacheTimeDefault() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(300000L));
	}
	
	@Test
	public void getExternalConfig() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(ImmutableMap.of(
								"thing", ConfigItem.state("foo"),
								"nothing", ConfigItem.state("bar")))));
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(new TestExternalConfig<>(ConfigItem.state("foo"))));
	}
	
	@Test
	public void getExternalConfigFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetExternalConfig(auth, null, new NullPointerException("mapper"));
	}
	
	@Test
	public void getExternalConfigFailMappingError() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetExternalConfig(auth, new FailingMapper(),
				new ExternalConfigMappingException("always fails"));
	}
	
	private <T extends ExternalConfig> void failGetExternalConfig(
			final Authentication auth,
			final ExternalConfigMapper<T> mapper,
			final Exception e) {
		try {
			auth.getExternalConfig(mapper);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void updateConfig() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final AuthConfigUpdate<ExternalConfig> update =
				AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
	}
	
	@Test
	public void updateConfigFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failUpdateConfig(auth, null, AuthConfigUpdate.getBuilder().build(),
				new NullPointerException("token"));
		failUpdateConfig(auth, new IncomingToken("foo"), null, new NullPointerException("update"));
	}
	
	@Test
	public void updateConfigExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.updateConfig(token, AuthConfigUpdate.getBuilder().build());
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void updateConfigFailNoSuchProvider() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		failUpdateConfig(auth, token, AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov3", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build(),
				new NoSuchIdentityProviderException("prov3"));
	}
	
	@Test
	public void updateConfigFailNoSuchProviderCase() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		failUpdateConfig(auth, token, AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("Prov1", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build(),
				new NoSuchIdentityProviderException("Prov1"));
	}
	
	private void failUpdateConfig(
			final Authentication auth,
			final IncomingToken token,
			final AuthConfigUpdate<ExternalConfig> update,
			final Exception e) {
		try {
			auth.updateConfig(token, update);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void resetConfig() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		auth.resetConfigToDefault(token);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov1", new ProviderUpdate(false, false, false))
				.withProviderUpdate("prov2", new ProviderUpdate(false, false, false))
				.withDefaultTokenLifeTimes()
				.withExternalConfig(AuthenticationTester.TEST_EXTERNAL_CONFIG)
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
	}
	
	@Test
	public void resetConfigFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		try {
			auth.resetConfigToDefault(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	@Test
	public void resetConfigExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.resetConfigToDefault(token);
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}

}

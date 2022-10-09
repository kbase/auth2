package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.lib.AuthenticationTester.setupValidUserResponses;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigSetWithUpdateTime;
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
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;
import us.kbase.test.auth2.lib.config.FailConfig.FailingMapper;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class AuthenticationConfigTest {
	
	private static List<ILoggingEvent> logEvents;
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
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
		final IdentityProvider idp3 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		when(idp3.getProviderName()).thenReturn("prov3");
		
		final TestMocks testauth = initTestMocks(set(idp1, idp2, idp3));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final AuthConfigUpdate<ExternalConfig> update =
				AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov3", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov2", new ProviderUpdate(false, false, false))
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.SERV, 700000)
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withTokenLifeTime(TokenLifetimeType.AGENT, 800000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov3", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov2", new ProviderUpdate(false, false, false))
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withTokenLifeTime(TokenLifetimeType.SERV, 700000)
				.withTokenLifeTime(TokenLifetimeType.DEV, 300000)
				.withTokenLifeTime(TokenLifetimeType.AGENT, 800000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
		
		final Class<?> c = Authentication.class;
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "Admin foo set non-admin login allowed to false", c),
				new LogEvent(Level.INFO, "Admin foo set lifetime for token type AGENT to 800000",
						c),
				new LogEvent(Level.INFO, "Admin foo set lifetime for token type DEV to 300000", c),
				new LogEvent(Level.INFO, "Admin foo set lifetime for token type SERV to 700000",
						c),
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov1. " +
						"Enabled: false Force login choice: true Force link choice: false", c),
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov2. " +
						"Enabled: false Force login choice: false Force link choice: false", c),
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov3. " +
						"Enabled: true Force login choice: true Force link choice: true", c),
				new LogEvent(Level.INFO, "Admin foo set external config key thing to foo", c)
		);
	}
	
	@Test
	public void updateConfigNoChanges() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final AuthConfigUpdate<ExternalConfig> update = AuthConfigUpdate.getBuilder().build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder().build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));

		assertThat("Expected no log events", logEvents.isEmpty(), is(true));
	}
	
	@Test
	public void updateConfigNoopProviderAndExternalRemove() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final Optional<Boolean> abs = Optional.empty();
		final AuthConfigUpdate<ExternalConfig> update =
				AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(abs, abs, abs))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.remove()))
				.build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(abs, abs, abs))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.remove()))
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
		
		final Class<?> c = Authentication.class;
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "Admin foo set non-admin login allowed to true", c),
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov2. " +
						"Enabled: true Force login choice: false Force link choice: true", c),
				new LogEvent(Level.INFO, "Admin foo removed external config key thing",
						c)
		);
	}
	
	@Test
	public void updateConfigProviderEnableOnlyAndExternalNoAction() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		
		final TestMocks testauth = initTestMocks(set(idp1));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final Optional<Boolean> abs = Optional.empty();
		final AuthConfigUpdate<ExternalConfig> update =
				AuthConfigUpdate.getBuilder()
				.withProviderUpdate("prov1", new ProviderUpdate(Optional.of(true), abs, abs))
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.noAction()))
				.build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withProviderUpdate("prov1", new ProviderUpdate(Optional.of(true), abs, abs))
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.noAction()))
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
		
		final Class<?> c = Authentication.class;
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov1. " +
						"Enabled: true", c)
		);
	}
	
	@Test
	public void updateConfigProviderForceChoiceOnly() throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		
		final TestMocks testauth = initTestMocks(set(idp1));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		final Optional<Boolean> abs = Optional.empty();
		final AuthConfigUpdate<ExternalConfig> update =
				AuthConfigUpdate.getBuilder()
				.withProviderUpdate("prov1",
						new ProviderUpdate(abs, Optional.of(true), Optional.of(false)))
				.build();
		auth.updateConfig(token, update);
		
		verify(storage).updateConfig(AuthConfigUpdate.getBuilder()
				.withProviderUpdate("prov1",
						new ProviderUpdate(abs, Optional.of(true), Optional.of(false)))
				.build(), true);
		
		verify(storage).getConfig(isA(CollectingExternalConfigMapper.class));
		
		final Class<?> c = Authentication.class;
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "Admin foo set values for identity provider prov1. " +
						"Force login choice: true Force link choice: false", c)
		);
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
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.updateConfig(token, AuthConfigUpdate.getBuilder().build());
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "update configuration";
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
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin foo reset the configuration to defaults", Authentication.class));
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
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.resetConfigToDefault(token);
			}
			
			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "reset configuration";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void getConfig() throws Exception {
		/* This tests filtering providers in the storage system that aren't registered on 
		 * startup
		 */
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		
		when(idp1.getProviderName()).thenReturn("prov1");
		when(idp2.getProviderName()).thenReturn("prov2");
		
		final TestMocks testauth = initTestMocks(set(idp1,idp2));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		AuthenticationTester.setConfigUpdateInterval(auth, 1);
		Thread.sleep(1001);
		
		setupValidUserResponses(storage, new UserName("foo"), Role.ADMIN, token);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true,
								ImmutableMap.of(
										"prov1", new ProviderConfig(true, false, true),
										"prov2", new ProviderConfig(true, false, false),
										"prov3", new ProviderConfig(false, false, true)),
								ImmutableMap.of(TokenLifetimeType.DEV, 300000L)),
						new CollectingExternalConfig(
								ImmutableMap.of("thing", ConfigItem.state("whiz")))))
				.thenReturn(null);
		
		final AuthConfigSetWithUpdateTime<TestExternalConfig<State>> res =
				auth.getConfig(token, new TestExternalConfigMapper());
		
		assertThat("incorrect config state", res, is(new AuthConfigSetWithUpdateTime<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, false, true),
								"prov2", new ProviderConfig(true, false, false)),
						ImmutableMap.of(TokenLifetimeType.DEV, 300000L)),
				new TestExternalConfig<>(ConfigItem.state("whiz")),
				1)));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Admin foo accessed the configuration", Authentication.class));
	}
	
	@Test
	public void getConfigFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetConfig(auth, null, new TestExternalConfigMapper(),
				new NullPointerException("token"));
		failGetConfig(auth, new IncomingToken("foo"), null, new NullPointerException("mapper"));
	}
	
	@Test
	public void getConfigExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getConfig(token, new TestExternalConfigMapper());
			}
			
			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}

			@Override
			public String getOperationString() {
				return "get configuration";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	private <T extends ExternalConfig> void failGetConfig(
			final Authentication auth,
			final IncomingToken token,
			final ExternalConfigMapper<T> mapper,
			final Exception e) {
		try {
			auth.getConfig(token, mapper);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void configManager() throws Exception {
		/* Tons of methods interact with the config manager, way too many to test every single
		 * one with config update timing. Hence we'll just test the update timing with one method
		 * to check getting the entire config and one method to check getting the app config only.
		 * 
		 * All the other methods *should* be tested with code that runs through the config
		 * manager, but probably doesn't exercise the update timing.
		 */
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.EXT_CACHE, 400000L)),
						new CollectingExternalConfig(ImmutableMap.of(
								"thing", ConfigItem.state("foo1"),
								"nothing", ConfigItem.state("bar1")))))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.EXT_CACHE, 500000L)),
						new CollectingExternalConfig(ImmutableMap.of(
								"thing", ConfigItem.state("foo2"),
								"nothing", ConfigItem.state("bar2")))))
				.thenReturn(null);
		
		final TestExternalConfig<State> exp0 = new TestExternalConfig<>(
				ConfigItem.state(AuthenticationTester.TEST_EXTERNAL_CONFIG.aThing.getItem()));
		final TestExternalConfig<State> exp1 = new TestExternalConfig<>(ConfigItem.state("foo1"));
		final TestExternalConfig<State> exp2 = new TestExternalConfig<>(ConfigItem.state("foo2"));

		AuthenticationTester.setConfigUpdateInterval(auth, 200);

		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(exp0));
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(300000L));
		
		Thread.sleep(100);
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(exp0));
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(300000L));
		
		Thread.sleep(101);
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(exp1));
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(400000L));
		
		Thread.sleep(100);
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(exp1));
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(400000L));
		
		Thread.sleep(101);
		
		assertThat("incorrect external config", auth.getExternalConfig(
				new TestExternalConfigMapper()),
				is(exp2));
		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(500000L));
	}
	
	@Test
	public void configManagerFail() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenThrow(
				new ExternalConfigMappingException("foo"));
		
		AuthenticationTester.setConfigUpdateInterval(auth, 200);

		assertThat("incorrect cache time", auth.getSuggestedTokenCacheTime(), is(300000L));
		
		Thread.sleep(201);
		
		try {
			auth.getSuggestedTokenCacheTime();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got,
					new RuntimeException("This should be impossible"));
		}
	}
}

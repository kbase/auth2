package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.TestCommon.tempToken;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.OAuth2StartData;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityProviderErrorException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationLinkTest {
	
	private final Instant NOW = Instant.now();
	
	private final RemoteIdentity REMOTE = new RemoteIdentity(new RemoteIdentityID("Prov", "id1"),
			new RemoteIdentityDetails("user1", "full1", "f1@g.com"));
	
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
	public void linkStartDefaultEnv() throws Exception {
		linkStart("ip1", null, "https://defaultenv.com");
	}
	@Test
	public void linkStartUpperCaseProviderDefaultEnv() throws Exception {
		// test case insensitivity for providers
		linkStart("Ip1", null, "https://defaultenv.com");
	}
	
	@Test
	public void linkStartSpecifyEnv() throws Exception {
		linkStart("ip1", "env2", "https://env2.com");
	}
	
	private void linkStart(final String provider, final String env, final String expectedURI)
			throws Exception {
		final TestMocks testauth = initTestMocks(false, true);
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		final IdentityProvider ip = testauth.prov1;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(rand.getToken())
				.thenReturn("statetokenhere").thenReturn("sometoken").thenReturn(null);
		when(ip.getLoginURI("statetokenhere", true, null))
				.thenReturn(new URI("https://defaultenv.com")).thenReturn(null);
		when(ip.getLoginURI("statetokenhere", true, "env2"))
				.thenReturn(new URI("https://env2.com")).thenReturn(null);
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000));
		
		final OAuth2StartData sd = auth.linkStart(userToken, 60, provider, env);
		
		assertThat("incorrect start data", sd,
				is(OAuth2StartData.build(
						new URI(expectedURI),
						tempToken(tokenID, Instant.ofEpochMilli(20000), 60000, "sometoken"),
						"statetokenhere")
				));
				
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 60 * 1000).link(new UserName("baz")),
				IncomingToken.hash("sometoken"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Created temporary link token %s associated with user baz", tokenID),
				Authentication.class));
	}
	
	@Test
	public void linkStartExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public TestMocks getTestMocks() throws Exception {
				return initTestMocks(false, true);
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.linkStart(getIncomingToken(), 120, "Ip1", "environment");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "start link";
			}
		}, set());
	}
	
	@Test
	public void linkStartFailBadInput() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken t = new IncomingToken("foo");
		
		failLinkStart(auth, null, 60, "id", "env", new NullPointerException("token"));
		failLinkStart(auth, t, 59, "id", "env",
				new IllegalArgumentException("lifetimeSec must be at least 60"));
		failLinkStart(auth, t, 60, null, "env", new MissingParameterException("provider"));
		failLinkStart(auth, t, 60, "   \t   \n  ", "env",
				new MissingParameterException("provider"));
	}
	
	@Test
	public void linkStartFailNoProvider() throws Exception {
		linkStartFailNoProvider("Prov3", new NoSuchIdentityProviderException("Prov3"));
		linkStartFailNoProvider("Prov2", new NoSuchIdentityProviderException("Prov2"));
	}
	
	private void linkStartFailNoProvider(final String provider, final Exception expected)
			throws Exception {
		final IdentityProvider idp1 = mock(IdentityProvider.class);
		when(idp1.getProviderName()).thenReturn("Prov1");
		final IdentityProvider idp2 = mock(IdentityProvider.class);
		when(idp2.getProviderName()).thenReturn("Prov2");

		final TestMocks mocks = initTestMocks(set(idp1, idp2));
		
		final Authentication auth = mocks.auth;
		final AuthStorage storage = mocks.storageMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov1", new ProviderConfig(true, false, false),
				"Prov2", new ProviderConfig(false, false, false) // disabled
		);

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkStart(auth, token, 120, provider, null, expected);
	}
	
	@Test
	public void linkStartFailLocalUser() throws Exception {
		final TestMocks testauth = initTestMocks(false, true);
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(testauth.randGenMock.getToken())
				.thenReturn("statetokenhere").thenReturn(null);
		when(testauth.prov1.getLoginURI("statetokenhere", true, null))
				.thenReturn(new URI("https://defaultenv.com")).thenReturn(null);
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.build()).thenReturn(null);
		
		failLinkStart(auth, userToken, 120, "ip1", "env", new LinkFailedException(
				"Cannot link identities to local account baz"));
	}
	
	private void failLinkStart(
			final Authentication auth,
			final IncomingToken token,
			final int lifetimeSec,
			final String idProvider,
			final String environment,
			final Exception e) {
		try {
			auth.linkStart(token, lifetimeSec, idProvider, environment);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void linkWithTokenImmediately() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.empty()).thenReturn(null);

		when(storage.link(new UserName("baz"), storageRemoteID)).thenReturn(true);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", null);
		
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect linktoken", lt, is(new LinkToken()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Linked identity fda04183ab36b12041695c2f78f07713 Prov id2 user2 to user baz",
				Authentication.class));
	}
	
	
	@Test
	public void linkWithTokenImmediatelyUpdateRemoteIdentity() throws Exception {
		/* tests the scenario when a link is requested but a race condition means that the
		 * single returned identity has been added to the user after the set of identities have
		 * been filtered
		 */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.empty()).thenReturn(null);
		// 2nd identity would be added after this point but before the link call below

		when(storage.link(new UserName("baz"), storageRemoteID)).thenReturn(false);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", null);
		
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect linktoken", lt, is(new LinkToken()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Identity fda04183ab36b12041695c2f78f07713 Prov id2 user2 is already " +
				"linked to user baz", Authentication.class));
	}
	
	@Test
	public void linkWithTokenRaceConditionAndIDLinked() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
				new RemoteIdentity(
						new RemoteIdentityID("Prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "f3@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.empty()).thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("whee"), new DisplayName("arg"), Instant.now())
				.withIdentity(storageRemoteID3).build())).thenReturn(null);
		
		when(storage.link(new UserName("baz"), storageRemoteID2))
				.thenThrow(new IdentityLinkedException("foo"));
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", null);
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(tempToken(
				tokenID, Instant.ofEpochMilli(10000), 10 * 60 * 1000, "foobar"))));
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(10000), 600000)
				.link(new UserName("baz"), set(storageRemoteID2, storageRemoteID3)),
				IncomingToken.hash("foobar"));
		
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"A race condition means that the identity fda04183ab36b12041695c2f78f07713 " +
				"is already linked to a user other than baz. Stored identity set with 2 linked " +
				"identities with temporary token %s", tokenID), Authentication.class));
	}
	
	@Test
	public void linkWithTokenForceChoiceWithEnvironment() throws Exception {
		// tests the non-standard environment
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, true));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, "myenv")).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.empty()).thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", "myenv");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(tempToken(
				tokenID, Instant.ofEpochMilli(10000), 10 * 60 * 1000, "foobar"))));
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(10000), 600000)
				.link(new UserName("baz"), set(storageRemoteID)),
				IncomingToken.hash("foobar"));

		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		verify(storage, never()).link(any(), any());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 1 link identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void linkWithTokenNoAvailableIDsDueToFilter() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", null);
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(tempToken(
				tokenID, Instant.ofEpochMilli(10000), 10 * 60 * 1000, "foobar"))));
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(10000), 600000)
				.link(new UserName("baz"), set(storageRemoteID)),
				IncomingToken.hash("foobar"));

		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		verify(storage, never()).link(any(), any());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 1 link identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void linkWithTokenWith2IDs1Filtered() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
						new RemoteIdentityDetails("user4", "full4", "f4@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		final RemoteIdentity storageRemoteID4 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "f4@g.com"));
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.empty())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.empty())
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode", null);
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(tempToken(
				tokenID, Instant.ofEpochMilli(10000), 10 * 60 * 1000, "foobar"))));
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(10000), 600000)
				.link(new UserName("baz"),
						set(storageRemoteID2, storageRemoteID3, storageRemoteID4)),
				IncomingToken.hash("foobar"));

		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		verify(storage, never()).link(any(), any());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 3 link identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void linkWithTokenFailNullsAndEmpties() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build());
		
		failLinkWithToken(auth, null, "prov", "foo", null,
				new NullPointerException("Temporary token"));
		failLinkWithToken(auth, token, null, "foo", null,
				new MissingParameterException("provider"));
		failLinkWithToken(auth, token, "  \t ", "foo", null,
				new MissingParameterException("provider"));
		failLinkWithToken(auth, token, "prov", null, null,
				new MissingParameterException("authorization code"));
		failLinkWithToken(auth, token, "prov", "  \n  ", null,
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void linkWithTokenFailNoProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		failLinkWithToken(auth, token, "prov1", "foo", null,
				new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void linkWithTokenFailNoProviderInConfig() throws Exception {
		/* this case indicates a programming error, a provider should never be in the internal
		 * Authorization class state but not in the config in the db
		 */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov1", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkWithToken(auth, token, "prov", "foo", null,
				new NoSuchIdentityProviderException("Prov"));
	}
	
	@Test
	public void linkWithTokenFailDisabledProvider() throws Exception {
		/* this case indicates a programming error, a provider should never be in the internal
		 * Authorization class state but not in the config in the db
		 */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(false, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkWithToken(auth, token, "prov", "foo", null,
				new NoSuchIdentityProviderException("prov"));
	}
	
	@Test
	public void linkWithTokenFailBadToken() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenThrow(
				new NoSuchTokenException("foo"));
		
		failLinkWithToken(auth, token, "prov", "foo", null,
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void linkWithTokenFailBadTokenOp() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final UUID tid = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(tid, Instant.now(), Instant.now())
				.login(set(REMOTE)))
				.thenReturn(null);
		
		failLinkWithToken(auth, token, "prov", "foo", null, new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"Operation LINKSTART was attempted with a LOGINIDENTS temporary token " + tid,
				Authentication.class));
	}
	
	@Test
	public void linkWithTokenFailBadTokenOpWithUser() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final UUID tid = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(tid, Instant.now(), Instant.now())
				.link(new UserName("whee"), set(REMOTE)))
				.thenReturn(null);
		
		failLinkWithToken(auth, token, "prov", "foo", null, new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User whee attempted operation LINKSTART with a LINKIDENTS temporary token " + tid,
				Authentication.class));
	}
	
	@Test
	public void linkWithTokenFailNoUserForToken() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenThrow(new NoSuchUserException("baz"));
		
		failLinkWithToken(auth, token, "prov", "foo", null, new RuntimeException(
				"There seems to be an error in the storage system. Token was valid, but no user"));
	}
	
	@Test
	public void linkWithTokenFailDisabledUser() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("f"), Instant.now())
				.withUserDisabledState(
						new UserDisabledState("f", new UserName("b"), Instant.now())).build());
		
		failLinkWithToken(auth, token, "prov", "foo", null, new DisabledUserException("baz"));

		verify(storage).deleteTokens(new UserName("baz"));
	}
	
	@Test
	public void linkWithTokenFailLocalUser() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("foo")));
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());
		
		failLinkWithToken(auth, token, "prov", "foo", null,
				new LinkFailedException("Cannot link identities to local account foo"));
	}
	
	@Test
	public void linkWithTokenFailNoSuchEnv() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("foo")));
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withIdentity(REMOTE).build());
		
		when(idp.getIdentities("foo", true, "env")).thenThrow(
				new NoSuchEnvironmentException("env"));
		
		failLinkWithToken(auth, token, "prov", "foo", "env",
				new NoSuchEnvironmentException("env"));
	}
	
	@Test
	public void linkWithTokenFailIDRetrievalFailed() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("foo")));
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withIdentity(REMOTE).build());
		
		when(idp.getIdentities("foo", true, null)).thenThrow(
				new IdentityRetrievalException("oh poop"));
		
		failLinkWithToken(auth, token, "prov", "foo", null,
				new IdentityRetrievalException("oh poop"));
	}
	
	@Test
	public void linkWithTokenFailNoSuchUserOnLink() throws Exception {
		/* another one that should be impossible */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.empty()).thenReturn(null);
		
		doThrow(new NoSuchUserException("baz"))
				.when(storage).link(new UserName("baz"), storageRemoteID);
		
		failLinkWithToken(auth, token, "prov", "authcode", null, new AuthStorageException(
				"User unexpectedly disappeared from the database"));
	}
	
	@Test
	public void linkWithTokenFailLinkFailedOnLink() throws Exception {
		/* another one that should be impossible */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), Instant.now(), Instant.now())
						.link(new UserName("baz")));
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.empty()).thenReturn(null);
		
		doThrow(new LinkFailedException("doodoo"))
				.when(storage).link(new UserName("baz"), storageRemoteID);
		
		failLinkWithToken(auth, token, "prov", "authcode", null,
				new LinkFailedException("doodoo"));
	}
	
	private void failLinkWithToken(
			final Authentication auth,
			final IncomingToken token,
			final String provider,
			final String authcode,
			final String env,
			final Exception e) {
		try {
			auth.link(token, provider, authcode, env);
			fail("exception expected");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void linkProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final UUID id = UUID.randomUUID();
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000));
		when(rand.getToken()).thenReturn("mytoken");
		when(rand.randomUUID()).thenReturn(id);
		
		final TemporaryToken tt = auth.linkProviderError("errthing");
		
		final TemporaryToken expected = tempToken(
				id, Instant.ofEpochMilli(20000), 10 * 60 * 1000, "mytoken");
		
		assertThat("incorrect login token", tt, is(expected));
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				id, Instant.ofEpochMilli(20000), 600000)
				.error("errthing", ErrorType.ID_PROVIDER_ERROR),
				IncomingToken.hash("mytoken"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR, String.format(
				"Stored temporary token %s with link identity provider error errthing", id),
				Authentication.class));
	}
	
	@Test
	public void linkProviderErrorFail() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failLinkProviderError(auth, null, new IllegalArgumentException(
				"Missing argument: providerError"));
		failLinkProviderError(auth, "   \t   ", new IllegalArgumentException(
				"Missing argument: providerError"));
	}
	
	private void failLinkProviderError(
			final Authentication auth,
			final String error,
			final Exception e) {
		try {
			auth.linkProviderError(error);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getLinkState() throws Exception {
		/* tests id filtering */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID temptokenid = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(temptokenid, Instant.ofEpochMilli(1000),
						Instant.ofEpochMilli(20000))
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "f4@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		final RemoteIdentity storageRemoteID4 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "f4@g.com"));
		
		final AuthUser user2 = AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now())
				.withIdentity(storageRemoteID2).build();
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(user2))
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.empty())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.empty())
				.thenReturn(null);
		
		final LinkIdentities li = auth.getLinkState(userToken, tempToken);
		
		assertThat("incorrect link identities", li, is(LinkIdentities.getBuilder(
				new UserName("baz"), "prov", Instant.ofEpochMilli(20000))
				.withUser(user2, storageRemoteID2)
				.withIdentity(storageRemoteID3)
				.withIdentity(storageRemoteID4).build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"User baz accessed temporary link token %s with 3 identities", temptokenid),
				Authentication.class));
	}
	
	@Test
	public void getLinkStateNoUnlinkedIDs() throws Exception {
		/* tests id filtering */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID tempTokenID = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(tempTokenID, NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));

		final AuthUser user2 = AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now())
				.withIdentity(storageRemoteID2).build();
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(user2)).thenReturn(null);
		
		final LinkIdentities li = auth.getLinkState(userToken, tempToken);
		
		assertThat("incorrect link identities", li, is(LinkIdentities.getBuilder(
				new UserName("baz"), "prov", NOW)
				.withUser(user2, storageRemoteID2)
				.build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"User baz accessed temporary link token %s with 1 identities", tempTokenID),
				Authentication.class));
	}
	
	@Test
	public void getLinkStateFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		failGetLinkState(auth, null, tempToken, new NullPointerException("token"));
		failGetLinkState(auth, userToken, null, new NullPointerException("Temporary token"));
	}
	
	@Test
	public void getLinkStateExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getLinkState(getIncomingToken(), new IncomingToken("foobarbaz"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get link state";
			}
		}, set());
	}
	
	@Test
	public void getLinkStateFailLocalUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());

		failGetLinkState(auth, token, new IncomingToken("bar"),
				new LinkFailedException("Cannot link identities to local account foo"));
	}
	
	@Test
	public void getLinkStateFailBadTempToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failGetLinkState(auth, userToken, tempToken, new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void getLinkStateFailProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken,
				new IdentityProviderErrorException("errthing"));
	}
	
	@Test
	public void getLinkStateFailUnknownError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing", ErrorType.UNSUPPORTED_OP))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken,
				new RuntimeException("Unexpected error type UNSUPPORTED_OP"));
	}
	
	@Test
	public void getLinkStateFailBadTokenOp() throws Exception {
		/* tests id filtering */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID tempTokenID = UUID.randomUUID();
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(tempTokenID, NOW, NOW)
				.login(set(REMOTE)))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken, new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User baz attempted operation LINKIDENTS with a LOGINIDENTS temporary token " +
				tempTokenID, Authentication.class));
	}
	
	@Test
	public void getLinkStateFailTempTokenUser() throws Exception {
		/* tests id filtering */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID tempTokenID = UUID.randomUUID();
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(tempTokenID, NOW, NOW)
				.link(new UserName("bad"), set(REMOTE)))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken,
				new UnauthorizedException("User baz may not access this identity set"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR, String.format(
				"During the account linking process user baz attempted to access temporary " +
				"token %s which is owned by user bad.", tempTokenID), Authentication.class));
	}

	private void failGetLinkState(
			final Authentication auth,
			final IncomingToken utoken,
			final IncomingToken ttoken,
			final Exception e) {
		try {
			auth.getLinkState(utoken, ttoken);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void linkIdentity() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "f4@g.com")))))
				.thenReturn(null);
		
		when(storage.link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com")))).thenReturn(true);
		
		auth.link(userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2");
		
		verify(storage).deleteTemporarySessionData(tempToken.getHashedToken());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Linked identity de0702aa7927b562e0d6be5b6527cfb2 prov id3 user3 to user baz",
				Authentication.class));
	}
	
	@Test
	public void linkIdentityUpdateRemoteIdentity() throws Exception {
		/* tests the scenario when a link is requested but a race condition means that the
		 * single returned identity has been added to the user after the set of identities have
		 * been filtered
		 */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "f4@g.com")))))
				.thenReturn(null);

		// 2nd identity would be added after this point but before the link call below

		when(storage.link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com")))).thenReturn(false);
		
		auth.link(userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2");
		
		verify(storage).deleteTemporarySessionData(tempToken.getHashedToken());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Identity de0702aa7927b562e0d6be5b6527cfb2 prov id3 user3 is already " +
				"linked to user baz",
				Authentication.class));
	}
	
	@Test
	public void linkIdentityFailNullsAndEmpties() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build());
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"), set(REMOTE)));

		failLinkIdentity(auth, null, tempToken, "foo", new NullPointerException("token"));
		failLinkIdentity(auth, userToken, null, "foo",
				new NullPointerException("Temporary token"));
		failLinkIdentity(auth, userToken, tempToken, null,
				new MissingParameterException("identityID"));
		failLinkIdentity(auth, userToken, tempToken, "  \t    ",
				new MissingParameterException("identityID"));
	}
	
	@Test
	public void linkIdentityExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.link(getIncomingToken(), new IncomingToken("foobar"), "whee");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "link identity whee";
			}
		}, set());
	}
	
	@Test
	public void linkIdentityFailLocalUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());

		failLinkIdentity(auth, token, new IncomingToken("bar"), "foo",
				new LinkFailedException("Cannot link identities to local account foo"));
	}
	
	@Test
	public void linkIdentityFailBadTempToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failLinkIdentity(auth, userToken, tempToken, "foo",
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void linkIdentityFailProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing1", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new IdentityProviderErrorException("errthing1"));
	}
	
	@Test
	public void linkIdentityFailBadTokenOp() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, NOW, NOW)
				.login(set(REMOTE)))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid", new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User baz attempted operation LINKIDENTS with a LOGINIDENTS temporary token " +
				id, Authentication.class));
	}
	
	@Test
	public void linkIdentityFailTempTokenUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, NOW, NOW)
				.link(new UserName("bad"), set(REMOTE)))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new UnauthorizedException("User baz may not access this identity set"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR, String.format(
				"During the account linking process user baz attempted to access temporary " +
				"token %s which is owned by user bad.", id), Authentication.class));
	}
	
	@Test
	public void linkIdentityFailUnexpectedError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing", ErrorType.LINK_FAILED))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new RuntimeException("Unexpected error type LINK_FAILED"));
	}
	
	@Test
	public void linkIdentityFailNoMatchingID() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")))))
				.thenReturn(null);

		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new LinkFailedException("User baz is not authorized to link identity fakeid"));
	}
	
	@Test
	public void linkIdentityFailNoSuchUserAtLink() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);

		doThrow(new NoSuchUserException("baz")).when(storage).link(new UserName("baz"),
				new RemoteIdentity(
						new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "f3@g.com")));
		
		failLinkIdentity(auth, userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2",
				new AuthStorageException("User magically disappeared from database: baz"));
	}
	
	@Test
	public void linkIdentityFailIdentityLinkedAtLink() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);

		doThrow(new IdentityLinkedException("de0702aa7927b562e0d6be5b6527cfb2"))
				.when(storage).link(new UserName("baz"), new RemoteIdentity(
						new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "f3@g.com")));
		
		failLinkIdentity(auth, userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2",
				new IdentityLinkedException("de0702aa7927b562e0d6be5b6527cfb2"));
	}
	
	@Test
	public void linkIdentityFailLinkFailedAtLink() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"),
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);

		doThrow(new LinkFailedException("foobar"))
				.when(storage).link(new UserName("baz"), new RemoteIdentity(
						new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "f3@g.com")));
		
		failLinkIdentity(auth, userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2",
				new RuntimeException(
						"Programming error: this method should not be called on a local user"));
	}
	
	
	private void failLinkIdentity(
			final Authentication auth,
			final IncomingToken utoken,
			final IncomingToken ttoken,
			final String id,
			final Exception e) {
		try {
			auth.link(utoken, ttoken, id);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void linkAll() throws Exception {
		/* tests filtering ids and ignoring link failures due to already linked ids */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"), set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "f4@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
								new RemoteIdentityDetails("user5", "full5", "f5@g.com")))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		final RemoteIdentity storageRemoteID4 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "f4@g.com"));
		final RemoteIdentity storageRemoteID5 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "f5@g.com"));
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.empty())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.empty())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID5)).thenReturn(Optional.empty())
				.thenReturn(null);
		
		doThrow(new IdentityLinkedException("foo")).when(storage)
				.link(new UserName("baz"), storageRemoteID3);

		when(storage.link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "f4@g.com"))))
				.thenReturn(true);
		
		when(storage.link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "f5@g.com"))))
				.thenReturn(false);
		// careful here, mockito returns false by default. Verify changing to true breaks the test
		
		auth.linkAll(userToken, tempToken);
		
		verify(storage).deleteTemporarySessionData(tempToken.getHashedToken());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Linked all 1 available identities to user baz", Authentication.class));
	}
	
	@Test
	public void linkAllNoAvailableIdentities() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"), set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.empty())
				.thenReturn(null);
		
		when(storage.link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
		// careful here, mockito returns false by default. Verify changing to true breaks the test
				.thenReturn(false);
		
		auth.linkAll(userToken, tempToken);
		
		verify(storage).deleteTemporarySessionData(tempToken.getHashedToken());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User baz had no available identities to link", Authentication.class));
	}
	
	@Test
	public void linkAllFailNullsAndEmpties() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build());
		
		failLinkAll(auth, null, tempToken, new NullPointerException("token"));
		failLinkAll(auth, userToken, null, new NullPointerException("Temporary token"));
	}
	
	@Test
	public void linkAllExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.linkAll(getIncomingToken(), new IncomingToken("foobar"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "link all identities";
			}
		}, set());
	}
	
	@Test
	public void linkAllFailLocalUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());

		failLinkAll(auth, token, new IncomingToken("bar"),
				new LinkFailedException("Cannot link identities to local account foo"));
	}
	
	@Test
	public void linkAllFailBadTempToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failLinkAll(auth, userToken, tempToken, new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void linkAllFailNoSuchUserAtLink() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"), set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemote3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		
		when(storage.getUser(storageRemote3)).thenReturn(Optional.empty());

		doThrow(new NoSuchUserException("baz")).when(storage).link(new UserName("baz"),
				storageRemote3);
		
		failLinkAll(auth, userToken, tempToken,
				new AuthStorageException("User magically disappeared from database: baz"));
	}
	
	@Test
	public void linkAllFailLinkFailProviderError() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing3", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failLinkAll(auth, userToken, tempToken, new IdentityProviderErrorException("errthing3"));
	}
	
	@Test
	public void linkAllFailLinkFailBadTokenOp() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, NOW, NOW)
				.login(set(REMOTE)))
				.thenReturn(null);
		
		failLinkAll(auth, userToken, tempToken,  new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User baz attempted operation LINKIDENTS with a LOGINIDENTS temporary token " +
				id, Authentication.class));
	}
	
	@Test
	public void linkAllFailLinkFailTempTokenUser() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, NOW, NOW)
				.link(new UserName("bad"), set(REMOTE)))
				.thenReturn(null);
		
		failLinkAll(auth, userToken, tempToken,
				new UnauthorizedException("User baz may not access this identity set"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR, String.format(
				"During the account linking process user baz attempted to access temporary " +
				"token %s which is owned by user bad.", id), Authentication.class));
	}
	
	@Test
	public void linkAllFailLinkFailUnexpectedError() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.error("errthing3", ErrorType.NO_TOKEN))
				.thenReturn(null);
		
		failLinkAll(auth, userToken, tempToken,
				new RuntimeException("Unexpected error type NO_TOKEN"));
	}
	
	@Test
	public void linkAllFailLinkFailedAtLink() throws Exception {
		/* tests id selection */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		final IncomingToken tempToken = new IncomingToken("temp");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(storage.getTemporarySessionData(tempToken.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), NOW, NOW)
				.link(new UserName("baz"), set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemote3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		
		when(storage.getUser(storageRemote3)).thenReturn(Optional.empty());

		doThrow(new LinkFailedException("foobar"))
				.when(storage).link(new UserName("baz"), storageRemote3);
		
		failLinkAll(auth, userToken, tempToken, new RuntimeException(
						"Programming error: this method should not be called on a local user"));
	}

	private void failLinkAll(
			final Authentication auth,
			final IncomingToken utoken,
			final IncomingToken ttoken,
			final Exception e) { 
		try {
			auth.linkAll(utoken, ttoken);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void unlink() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		auth.unlink(userToken, "foobar");
		
		verify(storage).unlink(new UserName("baz"), "foobar");
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Unlinked identity foobar from user baz", Authentication.class));
	}
	
	@Test
	public void unlinkFailNullsAndEmpties() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		failUnlink(auth, null, "foo", new NullPointerException("token"));
		failUnlink(auth, userToken, null, new MissingParameterException("identityID"));
		failUnlink(auth, userToken, "  \n \t  ", new MissingParameterException("identityID"));
	}
	
	@Test
	public void unlinkExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.unlink(getIncomingToken(), "whee");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "unlink identity whee";
			}
		}, set());
	}
	
	@Test
	public void unlinkFailLocalUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());

		failUnlink(auth, token, "foo",
				new UnLinkFailedException("Local user foo doesn't have remote identities"));
	}
	
	@Test
	public void unlinkFailAtUnlinkNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		doThrow(new NoSuchUserException("baz")).when(storage)
				.unlink(new UserName("baz"), "foobar");
		
		failUnlink(auth, userToken, "foobar", new AuthStorageException(
				"User magically disappeared from database: baz"));
	}
	
	@Test
	public void unlinkFailAtUnlinkUnlinkFailed() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		doThrow(new UnLinkFailedException("unlink")).when(storage)
				.unlink(new UserName("baz"), "foobar");
		
		failUnlink(auth, userToken, "foobar", new UnLinkFailedException("unlink"));
	}
	
	@Test
	public void unlinkFailAtUnlinkNoSuchIdentity() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken userToken = new IncomingToken("user");
		
		when(storage.getToken(userToken.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		doThrow(new NoSuchIdentityException("noid")).when(storage)
				.unlink(new UserName("baz"), "foobar");
		
		failUnlink(auth, userToken, "foobar", new NoSuchIdentityException("noid"));
	}
	
	private void failUnlink(
			final Authentication auth,
			final IncomingToken token,
			final String id,
			final Exception e) {
		try {
			auth.unlink(token, id);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}

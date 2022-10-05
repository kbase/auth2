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

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityProviderErrorException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationLoginTest {
	
	private static final Instant SMALL = Instant.ofEpochMilli(1);
	
	private static final TokenCreationContext CTX = TokenCreationContext.getBuilder().build();
	
	private static List<ILoggingEvent> logEvents;
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("r", "id7"),
			new RemoteIdentityDetails("user7", "full7", "f@g.com"));
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void loginImmediately() throws Exception {
		loginImmediately(Role.DEV_TOKEN, true);
		loginImmediately(Role.ADMIN, false);
		loginImmediately(Role.CREATE_ADMIN, false);
	}
	
	private void loginImmediately(
			final Role userRole,
			final boolean allowLogin)
			throws Exception {
		logEvents.clear();
		
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(allowLogin, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		final AuthUser user = AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000L))
				.withRole(userRole)
				.withIdentity(storageRemoteID).build();
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.of(user)).thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(Instant.ofEpochMilli(30000)).thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", null, TokenCreationContext.getBuilder()
				.withNullableAgent("a", "v").build());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder()
						.withNullableAgent("a", "v").build()).build(),
				"rIWdQ6H23g7MLjLjJTz8k7A6zEbn6+Cnwm5anDwasLc=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		final LoginToken expected = new LoginToken(
				new NewToken(StoredToken.getBuilder(
						TokenType.LOGIN, tokenID, new UserName("foo"))
						.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
						.withContext(TokenCreationContext.getBuilder()
								.withNullableAgent("a", "v").build()).build(),
						"thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Logged in user foo with token " + tokenID, Authentication.class));
	}
	
	@Test
	public void storeSingleIdentity() throws Exception {
		storeSingleLinkedIdentity(Role.DEV_TOKEN, false, false, false);
		storeSingleLinkedIdentity(Role.DEV_TOKEN, true, true, false);
		storeSingleLinkedIdentity(Role.ADMIN, true, false, false);
		storeSingleLinkedIdentity(Role.CREATE_ADMIN, true, false, false);
		storeSingleLinkedIdentity(Role.DEV_TOKEN, false, true, true);
		storeSingleLinkedIdentity(Role.ADMIN, false, false, true);
		storeSingleLinkedIdentity(Role.CREATE_ADMIN, false, false, true);
	}
	
	private void storeSingleLinkedIdentity(
			final Role userRole,
			final boolean disabled,
			final boolean allowLogin,
			final boolean forceLoginChoice)
			throws Exception {
		logEvents.clear();
		
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, forceLoginChoice, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(allowLogin, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		final AuthUser.Builder user = AuthUser.getBuilder(new UserName("foo"),
				new DisplayName("bar"), Instant.ofEpochMilli(10000L))
				.withRole(userRole)
				.withIdentity(storageRemoteID);
		if (disabled) {
			user.withUserDisabledState(new UserDisabledState(
					"d", new UserName("baz"), Instant.ofEpochMilli(5000)));
		}
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.of(user.build()))
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", null, CTX);
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000).login(set(storageRemoteID)),
				IncomingToken.hash("thisisatoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 1 login identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void storeUnlinkedIdentityWithEnvironment() throws Exception {
		// tests non standard environment
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, "env2")).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", "env2", CTX);
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000).login(set(storageRemoteID)),
				IncomingToken.hash("thisisatoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 1 login identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void storeLinkedAndUnlinkedIdentity() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID1 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"));
		
		when(storage.getUser(storageRemoteID1)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final AuthUser user = AuthUser.getBuilder(new UserName("foo"),
				new DisplayName("bar"), Instant.ofEpochMilli(10000L))
				.withIdentity(storageRemoteID2).build();
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(user))
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", null, CTX);
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000)
				.login(set(storageRemoteID1, storageRemoteID2)),
				IncomingToken.hash("thisisatoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 2 login identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void storeMultipleLinkedIdentities() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenReturn(set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID1 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"));
		
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"));
		
		
		final AuthUser user = AuthUser.getBuilder(new UserName("foo"),
				new DisplayName("bar"), Instant.ofEpochMilli(10000L))
				.withIdentity(storageRemoteID1)
				.withIdentity(storageRemoteID2).build();
		when(storage.getUser(storageRemoteID1)).thenReturn(Optional.of(user))
			.thenReturn(null);
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(
				AuthUser.getBuilderWithoutIdentities(user)
				.withIdentity(storageRemoteID1).withIdentity(storageRemoteID2).build()))
				.thenReturn(null);
		
		final AuthUser user2 = AuthUser.getBuilder(new UserName("foo2"),
				new DisplayName("bar2"), Instant.ofEpochMilli(50000L))
				.withIdentity(storageRemoteID3).build();
		
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.of(user2))
			.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", null, CTX);
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000)
				.login(set(storageRemoteID1, storageRemoteID2, storageRemoteID3)),
				IncomingToken.hash("thisisatoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 3 login identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void storeMultipleUnLinkedIdentities() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenReturn(set(
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")),
				new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
						new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID1 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"));
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"));
		
		final RemoteIdentity storageRemoteID3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"));
		
		
		when(storage.getUser(storageRemoteID1)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("thisisatoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000))
			.thenReturn(null);
		
		final LoginToken lt = auth.login("prov", "foobar", null, CTX);
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000)
				.login(set(storageRemoteID1, storageRemoteID2, storageRemoteID3)),
				IncomingToken.hash("thisisatoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				tokenID, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "thisisatoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Stored temporary token %s with 3 login identities", tokenID),
				Authentication.class));
	}
	
	@Test
	public void failLoginNullsAndEmpties() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		failLogin(auth, null, "foo", null, CTX, new NullPointerException("provider"));
		failLogin(auth, "   \t  \n   ", "foo", null, CTX,
				new NoSuchIdentityProviderException("   \t  \n   "));
		failLogin(auth, "prov", null, null, CTX,
				new MissingParameterException("authorization code"));
		failLogin(auth, "prov", "    \t \n   ", null, CTX,
				new MissingParameterException("authorization code"));
		failLogin(auth, "prov", "foo", null, null, new NullPointerException("tokenCtx"));
	}
	
	@Test
	public void failLoginNoSuchProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		failLogin(auth, "prov1", "foo", null, CTX, new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void failLoginDisabledProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(false, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLogin(auth, "prov", "foo", null, CTX, new NoSuchIdentityProviderException("prov"));
	}
	
	@Test
	public void failLoginIdentityRetrieval() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, null)).thenThrow(
				new IdentityRetrievalException("foo"));
		
		failLogin(auth, "prov", "foobar", null, CTX, new IdentityRetrievalException("foo"));
	}
	
	@Test
	public void failLoginNoSuchEnvironment() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foobar", false, "env1")).thenThrow(
				new NoSuchEnvironmentException("env1"));
		
		failLogin(auth, "prov", "foobar", "env1", CTX, new NoSuchEnvironmentException("env1"));
	}
	
	private void failLogin(
			final Authentication auth,
			final String provider,
			final String authcode,
			final String env,
			final TokenCreationContext ctx,
			final Exception e) {
		try {
			auth.login(provider, authcode, env, ctx);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void loginProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		
		final UUID id = UUID.randomUUID();
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(20000));
		when(rand.getToken()).thenReturn("mytoken");
		when(rand.randomUUID()).thenReturn(id);
		
		final LoginToken lt = auth.loginProviderError("errthing");
		
		verify(storage).storeTemporarySessionData(TemporarySessionData.create(
				id, Instant.ofEpochMilli(20000), 30 * 60 * 1000)
				.error("errthing", ErrorType.ID_PROVIDER_ERROR),
				IncomingToken.hash("mytoken"));
		
		final LoginToken expected = new LoginToken(tempToken(
				id, Instant.ofEpochMilli(20000), 30 * 60 * 1000, "mytoken"));
		
		assertThat("incorrect login token", lt, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR, String.format(
				"Stored temporary token %s with login identity provider error errthing", id),
				Authentication.class));
	}
	
	@Test
	public void loginProviderErrorFail() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failLoginProviderError(auth, null, new IllegalArgumentException(
				"Missing argument: providerError"));
		failLoginProviderError(auth, "   \t   ", new IllegalArgumentException(
				"Missing argument: providerError"));
	}
	
	private void failLoginProviderError(
			final Authentication auth,
			final String error,
			final Exception e) {
		try {
			auth.loginProviderError(error);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getLoginStateOneUnlinkedID() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.absent());
		
		final LoginState got = auth.getLoginState(token);
		
		final LoginState expected = LoginState.getBuilder(
				"prov", true, Instant.ofEpochMilli(10001))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Accessed temporary login token %s with 1 identities", id), Authentication.class));
	}
	
	@Test
	public void getLoginStateTwoUnlinkedIDsAndNoLoginAllowed() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		final LoginState got = auth.getLoginState(token);
		
		final LoginState expected = LoginState.getBuilder(
				"prov", false, Instant.ofEpochMilli(10001))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Accessed temporary login token %s with 2 identities", id), Authentication.class));
	}
	
	@Test
	public void getLoginStateOneLinkedID() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final AuthUser user = AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000L))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.of(user));
		
		final LoginState got = auth.getLoginState(token);
		
		final LoginState expected = LoginState.getBuilder("prov", true,Instant.ofEpochMilli(10001))
				.withUser(AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
						Instant.ofEpochMilli(10000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Accessed temporary login token %s with 1 identities", id), Authentication.class));
	}
	
	@Test
	public void getLoginStateTwoLinkedIDs() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final AuthUser user1 = AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000L))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		final AuthUser user2 = AuthUser.getBuilder(new UserName("foo2"), new DisplayName("bar2"),
				Instant.ofEpochMilli(20000L))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build();
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.of(user1));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.of(user2));
		
		
		final LoginState got = auth.getLoginState(token);
		
		
		final Instant exp = Instant.ofEpochMilli(10001);
		final LoginState expected = LoginState.getBuilder("prov", true, exp).withUser(
				AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
						Instant.ofEpochMilli(10000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
		
				.withUser(AuthUser.getBuilder(new UserName("foo2"), new DisplayName("bar2"),
						Instant.ofEpochMilli(20000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")))
				.build();
		
		assertThat("incorrect login state", got, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Accessed temporary login token %s with 2 identities", id), Authentication.class));
	}
	
	@Test
	public void getLoginStateOneLinkedOneUnlinkedID() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final AuthUser user = AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000L))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.of(user));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		
		final LoginState got = auth.getLoginState(token);
		
		final Instant exp = Instant.ofEpochMilli(10001);
		final LoginState expected = LoginState.getBuilder("prov", true, exp).withUser(
				AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
						Instant.ofEpochMilli(10000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")))
				.build();
		
		assertThat("incorrect login state", got, is(expected));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
				"Accessed temporary login token %s with 2 identities", id), Authentication.class));
	}
	
	@Test
	public void getLoginStateFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetLoginState(auth, null, new NullPointerException("Temporary token"));
	}
	
	@Test
	public void getLoginStateFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporarySessionData(token.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failGetLoginState(auth, token, new InvalidTokenException("Temporary token"));
	}

	@Test
	public void getLoginStateFailProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("err", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failGetLoginState(auth, token, new IdentityProviderErrorException("err"));
	}
	
	@Test
	public void getLoginStateFailUnexpectedError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("err", ErrorType.ID_ALREADY_LINKED))
				.thenReturn(null);
		
		failGetLoginState(auth, token, new RuntimeException(
				"Unexpected error type ID_ALREADY_LINKED"));
	}
	
	@Test
	public void getLoginStateFailBadTokenOp() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(id, SMALL, 10000)
						.link(new UserName("foo")))
				.thenReturn(null);

		failGetLoginState(auth, token, new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User foo attempted operation LOGINIDENTS with a LINKSTART temporary token " + id,
						Authentication.class));
	}
	
	private void failGetLoginState(
			final Authentication auth,
			final IncomingToken token,
			final Exception e) {
		try {
			auth.getLoginState(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void createUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				set(new PolicyID("pid1"), new PolicyID("pid2")),
				TokenCreationContext.getBuilder().withNullableDevice("d").build(), false);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withPolicyID(new PolicyID("pid1"), Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("pid2"), Instant.ofEpochMilli(10000)).build());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Created user foo linked to remote identity " +
						"ef0518c79af70ed979907969c6d0a0f7 prov id1 user1", Authentication.class),
				new LogEvent(Level.INFO, "Logged in user foo with token " + tokenID,
						Authentication.class));
	}
	
	@Test
	public void createUserAlternateTokenLifeTimeAndEmptyLinks() throws Exception {
		/* tests the case where link all is true but no links are available */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.LOGIN, 100000L)),
						new CollectingExternalConfig(Collections.emptyMap())));

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				set(new PolicyID("pid1"), new PolicyID("pid2")),
				TokenCreationContext.getBuilder().withNullableDevice("d").build(), true);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withPolicyID(new PolicyID("pid1"), Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("pid2"), Instant.ofEpochMilli(10000)).build());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 100000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 100000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Created user foo linked to remote identity " +
						"ef0518c79af70ed979907969c6d0a0f7 prov id1 user1", Authentication.class),
				new LogEvent(Level.INFO, "Logged in user foo with token " + tokenID,
						Authentication.class));
	}
	
	@Test
	public void createUserAndLinkAll() throws Exception {
		/* Tests the cases where some of the remote ids in the set are already linked when
		 * filtering or are linked between filtering and the storage.link() call
		 * 
		 * This is really damned long
		 */
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "d@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "c@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
								new RemoteIdentityDetails("user5", "full5", "b@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com"))))
				.thenReturn(Optional.of(NewUser.getBuilder(
						new UserName("baz"), new DisplayName("bar"), Instant.ofEpochMilli(700000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
						new RemoteIdentityDetails("user5", "full5", "b@g.com"))).build()));
		
		//the identity was linked after identity filtering. Code should just ignore this.
		when(storage.link(
				new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenThrow(new IdentityLinkedException("foo"));
		
		when(storage.link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
		.thenReturn(true);
		
		when(storage.link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com"))))
		.thenReturn(true);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				Collections.emptySet(),
				TokenCreationContext.getBuilder().withNullableDevice("d").build(), true);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com")).build());
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")));
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com")));

		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Created user foo linked to remote identity " +
						"ef0518c79af70ed979907969c6d0a0f7 prov id1 user1", Authentication.class),
				new LogEvent(Level.INFO, "Linked all 2 remaining identities to user foo",
						Authentication.class),
				new LogEvent(Level.INFO, "Logged in user foo with token " + tokenID,
						Authentication.class));
	}
	
	@Test
	public void createUserFailNullsAndEmpties() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, SMALL)
						.login(set(REMOTE)));
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, null, id, u, d, e, pids, CTX, l,
				new NullPointerException("Temporary token"));
		failCreateUser(auth, t, null, u, d, e, pids, CTX, l,
				new MissingParameterException("identityID"));
		failCreateUser(auth, t, "   \t   ", u, d, e, pids, CTX, l,
				new MissingParameterException("identityID"));
		failCreateUser(auth, t, id, null, d, e, pids, CTX, l, new NullPointerException("userName"));
		failCreateUser(auth, t, id, u, null, e, pids, CTX, l,
				new NullPointerException("displayName"));
		failCreateUser(auth, t, id, u, d, null, pids, CTX, l, new NullPointerException("email"));
		failCreateUser(auth, t, id, u, d, e, null, CTX, l, new NullPointerException("policyIDs"));
		failCreateUser(auth, t, id, u, d, e, set(new PolicyID("foo"), null), CTX, l,
				new NullPointerException("null item in policyIDs"));
		failCreateUser(auth, t, id, u, d, e, pids, null, l, new NullPointerException("tokenCtx"));
	}
	
	@Test
	public void createUserFailRoot() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken t = new IncomingToken("foo");
		final String id = "bar";
		final UserName u = UserName.ROOT;
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new UnauthorizedException(ErrorType.UNAUTHORIZED, "Cannot create ROOT user"));
	}
	
	@Test
	public void createUserFailLoginNotAllowed() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new UnauthorizedException(ErrorType.UNAUTHORIZED, "Account creation is disabled"));
	}
	
	@Test
	public void createUserFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void createUserFailProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("errthing", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new IdentityProviderErrorException("errthing"));
	}
	
	@Test
	public void createUserFailUnexpectedError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("errthing", ErrorType.DISABLED))
				.thenReturn(null);
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new RuntimeException("Unexpected error type DISABLED"));
	}
	
	@Test
	public void createUserFailBadTokenOp() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		final UUID tokenID = UUID.randomUUID();
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(tokenID, SMALL, 10000)
						.link(new UserName("foo")))
				.thenReturn(null);
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new InvalidTokenException(
						"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User foo attempted operation LOGINIDENTS with a LINKSTART temporary token "
				+ tokenID, Authentication.class));
	}
	
	@Test
	public void createUserFailNoMatchingIdentities() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		final String id = "bar"; //yep, that won't match
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Not authorized to create user with remote identity bar"));
	}
	
	@Test
	public void createUserFailUserExists() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L)).thenReturn(null);
		
		doThrow(new UserExistsException("baz")).when(storage).createUser(
				NewUser.getBuilder(new UserName("baz"), new DisplayName("bat"),
						Instant.ofEpochMilli(10000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.withEmailAddress(new EmailAddress("e@g.com")).build());
		
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l, new UserExistsException("baz"));
	}
	
	@Test
	public void createUserFailIdentityLinked() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L)).thenReturn(null);
		
		doThrow(new IdentityLinkedException("ef0518c79af70ed979907969c6d0a0f7")).when(storage)
				.createUser(NewUser.getBuilder(new UserName("baz"), new DisplayName("bat"),
						Instant.ofEpochMilli(10000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.withEmailAddress(new EmailAddress("e@g.com")).build());
		
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new IdentityLinkedException("ef0518c79af70ed979907969c6d0a0f7"));
	}
	
	@Test
	public void createUserFailNoRole() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L)).thenReturn(null);
		
		doThrow(new NoSuchRoleException("foobar")).when(storage)
				.createUser(NewUser.getBuilder(new UserName("baz"), new DisplayName("bat"),
						Instant.ofEpochMilli(10000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.withEmailAddress(new EmailAddress("e@g.com")).build());
		
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new RuntimeException("Didn't supply any roles"));
	}
	
	@Test
	public void createUserFailLinkAllNoSuchUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L)).thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		doThrow(new NoSuchUserException("baz")).when(storage).link(
				new UserName("baz"), new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l,
				new AuthStorageException("User magically disappeared from database: baz"));
	}
	
	@Test
	public void createUserFailLinkFailed() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L)).thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		doThrow(new LinkFailedException("local")).when(storage).link(
				new UserName("baz"), new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, CTX, l, new RuntimeException(
				"Programming error: this method should not be called on a local user"));
	}
	
	@Test
	public void createUserFailNoSuchUserOnSetLastLogin() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		doThrow(new NoSuchUserException("foo")).when(storage).setLastLogin(
				new UserName("foo"), Instant.ofEpochMilli(30000));
		
		failCreateUser(auth, token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				Collections.emptySet(), CTX, false, new AuthStorageException(
						"Something is very broken. User should exist but doesn't: " +
						"50000 No such user: foo"));
	}
	
	private void failCreateUser(
			final Authentication auth,
			final IncomingToken token,
			final String identityID,
			final UserName userName,
			final DisplayName displayName,
			final EmailAddress email,
			final Set<PolicyID> pids,
			final TokenCreationContext ctx,
			final boolean linkAll,
			final Exception e) {
		try {
			auth.createUser(token, identityID, userName, displayName, email, pids, ctx, linkAll);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void completeLogin() throws Exception {
		completeLogin(Role.DEV_TOKEN, true);
		completeLogin(Role.ADMIN, false);
		completeLogin(Role.CREATE_ADMIN, false);
	}

	private void completeLogin(final Role userRole, final boolean allowLogin)
			throws Exception {
		logEvents.clear();
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")))).thenReturn(Optional.of(
						AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
								Instant.ofEpochMilli(70000))
						.withRole(userRole)
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(allowLogin, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.login(token, "ef0518c79af70ed979907969c6d0a0f7",
				set(new PolicyID("pid1"),  new PolicyID("pid2")),
				TokenCreationContext.getBuilder().withNullableDevice("dev").build(), false);
		
		verify(storage).addPolicyIDs(new UserName("foo"),
				set(new PolicyID("pid1"), new PolicyID("pid2")));
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Logged in user foo with token " + tokenID, Authentication.class));
	}
	
	@Test
	public void completeLoginWithAlternateTokenLifetimeAndEmptyLinks() throws Exception {
		/* tests no policy ids case and link all with no available links case*/
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")))).thenReturn(Optional.of(
						AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
								Instant.ofEpochMilli(70000))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null,
								ImmutableMap.of(TokenLifetimeType.LOGIN, 600000L)),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.login(token, "ef0518c79af70ed979907969c6d0a0f7",
				Collections.emptySet(),
				TokenCreationContext.getBuilder().withNullableDevice("dev").build(), true);
		
		verify(storage, never()).addPolicyIDs(any(), any());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 600000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(610000))
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Logged in user foo with token " + tokenID, Authentication.class));
	}
	
	@Test
	public void completeLoginAndLinkAll() throws Exception {
		/* also tests no policy ids case
		 * this is also friggin huge
		 * 
		 * also tests linking all remaining identities when there's a race condition such that
		 * an identity is linked to the user after the identities are filtered, so the identity
		 * is updated rather than linked
		 */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();

		when(storage.getTemporarySessionData(token.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "d@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
								new RemoteIdentityDetails("user4", "full4", "c@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
								new RemoteIdentityDetails("user5", "full5", "b@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")))).thenReturn(Optional.of(
						AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
								Instant.ofEpochMilli(70000))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))
						.build()));

		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com"))))
				.thenReturn(Optional.absent());
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com"))))
				.thenReturn(Optional.of(NewUser.getBuilder(
						new UserName("baz"), new DisplayName("bar"), Instant.ofEpochMilli(700000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
						new RemoteIdentityDetails("user5", "full5", "b@g.com"))).build()));
		
		//the identity was linked after identity filtering. Code should just ignore this.
		when(storage.link(
				new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com"))))
				.thenThrow(new IdentityLinkedException("foo"));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
		.thenReturn(true);
		
		when(storage.link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com"))))
		.thenReturn(false);
		/* above means that the identity was linked to the user after the identities were filtered
		 * out, and so the identity was just updated rather than linked.
		 */
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.login(token, "ef0518c79af70ed979907969c6d0a0f7",
				Collections.emptySet(),
				TokenCreationContext.getBuilder().withNullableDevice("dev").build(), true);
		
		verify(storage, never()).addPolicyIDs(any(), any());
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")));
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com")));
		
		verify(storage).storeToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		verify(storage).deleteTemporarySessionData(token.getHashedToken());
		
		assertThat("incorrect new token", nt, is(new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, tokenID, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 14 * 24 * 3600 * 1000)
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("dev").build())
				.build(),
				"mfingtoken")));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
					"Linked all 1 remaining identities to user foo", Authentication.class),
				new LogEvent(Level.INFO,
						"Logged in user foo with token " + tokenID, Authentication.class));
	}
	
	@Test
	public void completeLoginFailNullsAndEmpties() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, SMALL)
						.login(set(REMOTE)));
		
		failCompleteLogin(auth, null, id, pids, CTX, l,
				new NullPointerException("Temporary token"));
		failCompleteLogin(auth, t, null, pids, CTX, l,
				new MissingParameterException("identityID"));
		failCompleteLogin(auth, t, "   \t   ", pids, CTX, l,
				new MissingParameterException("identityID"));
		failCompleteLogin(auth, t, id, null, CTX, l, new NullPointerException("policyIDs"));
		failCompleteLogin(auth, t, id, set(new PolicyID("foo"), null), CTX, l,
				new NullPointerException("null item in policyIDs"));
		failCompleteLogin(auth, t, id, pids, null, l, new NullPointerException("tokenCtx"));
	}
	
	@Test
	public void completeLoginFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void completeLoginFailProviderError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("errthing1", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failCompleteLogin(auth, t, id, pids, CTX, l,
				new IdentityProviderErrorException("errthing1"));
	}
	
	@Test
	public void completeLoginFailUnexpectedError() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.error("errthing", ErrorType.ILLEGAL_EMAIL_ADDRESS))
				.thenReturn(null);
		
		failCompleteLogin(auth, t, id, pids, CTX, l,
				new RuntimeException("Unexpected error type ILLEGAL_EMAIL_ADDRESS"));
	}
	
	@Test
	public void completeLoginFailBadTokenOp() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		final UUID tokenID = UUID.randomUUID();
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(tokenID, SMALL, 10000)
						.link(new UserName("whee")))
				.thenReturn(null);
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new InvalidTokenException(
				"Temporary token operation type does not match expected operation"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.ERROR,
				"User whee attempted operation LOGINIDENTS with a LINKSTART temporary token "
				+ tokenID, Authentication.class));
	}
	
	@Test
	public void completeLoginFailBadId() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee"; // definitely won't match anything
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		failCompleteLogin(auth, t, id, pids, CTX, l,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"Not authorized to login to user with remote identity whee"));
	}
	
	@Test
	public void completeLoginFailNoUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.absent());
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new AuthenticationException(
				ErrorType.AUTHENTICATION_FAILED,
				"There is no account linked to the provided identity ID"));
	}
	
	@Test
	public void completeLoginFailLoginDisabled() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new UnauthorizedException(
				ErrorType.UNAUTHORIZED,
				"User foo cannot log in because non-admin login is disabled"));
	}
	
	@Test
	public void completeLoginFailDisabledAccount() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com")))
					.withUserDisabledState(
							new UserDisabledState("foo", new UserName("baz"), Instant.now()))
					.build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new DisabledUserException("foo"));
	}
	
	@Test
	public void completeLoginFailNoSuchUserOnPolicyID() throws Exception {
		/* should be impossible, but might as well exercise */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = set(new PolicyID("foobaz"));
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.addPolicyIDs(new UserName("foo"), set(new PolicyID("foobaz")));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new AuthStorageException(
				"Something is very broken. User should exist but doesn't: " +
				"50000 No such user: foo"));
	}
	
	@Test
	public void completeLoginFailNoSuchUserOnLink() throws Exception {
		/* should be impossible, but might as well exercise */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build()));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
					.thenReturn(Optional.absent());
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.link(new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new AuthStorageException(
				"User magically disappeared from database: foo"));
	}
	
	@Test
	public void completeLoginFailLinkFailOnLink() throws Exception {
		/* should be impossible, but might as well exercise */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build()));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com"))))
					.thenReturn(Optional.absent());
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		doThrow(new LinkFailedException("foo")).when(storage)
				.link(new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new RuntimeException(
				"Programming error: this method should not be called on a local user"));
	}
	
	@Test
	public void completeLoginFailNoSuchUserOnSetLastLogin() throws Exception {
		/* should be impossible, but might as well exercise */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "ef0518c79af70ed979907969c6d0a0f7";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		when(storage.getTemporarySessionData(t.getHashedToken())).thenReturn(
				TemporarySessionData.create(UUID.randomUUID(), SMALL, 10000)
						.login(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com")))))
				.thenReturn(null);
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.of(AuthUser.getBuilder(new UserName("foo"),
							new DisplayName("bar"), Instant.ofEpochMilli(70000))
					.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
							new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build()));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), null);
		when(rand.randomUUID()).thenReturn(UUID.randomUUID()).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		doThrow(new NoSuchUserException("foo")).when(storage)
				.setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		
		failCompleteLogin(auth, t, id, pids, CTX, l, new AuthStorageException(
				"Something is very broken. User should exist but doesn't: " +
				"50000 No such user: foo"));
	}
	
	private void failCompleteLogin(
			final Authentication auth,
			final IncomingToken token,
			final String identityID,
			final Set<PolicyID> policyIDs,
			final TokenCreationContext ctx, 
			final boolean linkAll,
			final Exception e) {
		try {
			auth.login(token, identityID, policyIDs, ctx, linkAll);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

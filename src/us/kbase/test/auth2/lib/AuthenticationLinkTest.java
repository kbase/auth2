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
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.TemporaryIdentities;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityProviderErrorException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken()));
		
		verify(storage).link(new UserName("baz"), storageRemoteID);
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		doThrow(new IdentityLinkedException("foo"))
				.when(storage).link(new UserName("baz"), storageRemoteID);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("sometoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000))));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				Collections.emptySet());
	}
	
	@Test
	public void linkWithTokenForceChoice() throws Exception {
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("sometoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000))));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				set(storageRemoteID));
		
		verify(storage, never()).link(any(), any());
	}
	
	@Test
	public void linkWithTokenNoIDsDueToFilter() throws Exception {
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
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
		when(rand.getToken()).thenReturn("sometoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000))));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				Collections.emptySet());
		
		verify(storage, never()).link(any(), any());
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(
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
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("sometoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000))));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				set(storageRemoteID3, storageRemoteID4));
		
		verify(storage, never()).link(any(), any());
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build());
		
		failLinkWithToken(auth, null, "prov", "foo", new NullPointerException("token"));
		failLinkWithToken(auth, token, null, "foo", new NullPointerException("provider"));
		failLinkWithToken(auth, token, "  \t ", "foo",
				new NoSuchIdentityProviderException("  \t "));
		failLinkWithToken(auth, token, "prov", null,
				new MissingParameterException("authorization code"));
		failLinkWithToken(auth, token, "prov", "  \n  ",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void linkWithTokenFailNoProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		failLinkWithToken(auth, token, "prov1", "foo",
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
		
		failLinkWithToken(auth, token, "prov", "foo",
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
		
		failLinkWithToken(auth, token, "prov", "foo",
				new NoSuchIdentityProviderException("prov"));
	}
	
	@Test
	public void linkWithTokenExecuteStandardUserCheckingTests() throws Exception {
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public TestMocks getTestMocks() throws Exception {
				final IdentityProvider idp = mock(IdentityProvider.class);

				when(idp.getProviderName()).thenReturn("Prov");
				
				final TestMocks testauth = initTestMocks(set(idp));
				final AuthStorage storage = testauth.storageMock;
				final Authentication auth = testauth.auth;
				
				AuthenticationTester.setConfigUpdateInterval(auth, -1);

				final Map<String, ProviderConfig> providers = ImmutableMap.of(
						"Prov", new ProviderConfig(true, false, false));

				when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
						.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
								new AuthConfig(false, providers, null),
								new CollectingExternalConfig(Collections.emptyMap())));
				return testauth;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.link(getIncomingToken(), "prov", "foo");
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "link";
			}
		}, set());
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());
		failLinkWithToken(auth, token, "prov", "foo",
				new LinkFailedException("Cannot link identities to local accounts"));
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withIdentity(REMOTE).build());
		
		when(idp.getIdentities("foo", true)).thenThrow(new IdentityRetrievalException("oh poop"));
		
		failLinkWithToken(auth, token, "prov", "foo", new IdentityRetrievalException("oh poop"));
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		doThrow(new NoSuchUserException("baz"))
				.when(storage).link(new UserName("baz"), storageRemoteID);
		
		failLinkWithToken(auth, token, "prov", "authcode", new AuthStorageException(
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
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("Prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		doThrow(new LinkFailedException("doodoo"))
				.when(storage).link(new UserName("baz"), storageRemoteID);
		
		failLinkWithToken(auth, token, "prov", "authcode", new LinkFailedException("doodoo"));
	}
	
	private void failLinkWithToken(
			final Authentication auth,
			final IncomingToken token,
			final String provider,
			final String authcode,
			final Exception e) {
		try {
			auth.link(token, provider, authcode);
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
		
		final TemporaryToken expected = new TemporaryToken(
				id, "mytoken", Instant.ofEpochMilli(20000), 10 * 60 * 1000);
		
		assertThat("incorrect login token", tt, is(expected));
		
		verify(storage).storeErrorTemporarily(expected.getHashedToken(),
				"errthing", ErrorType.ID_PROVIDER_ERROR);
		
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
	public void linkWithoutToken() throws Exception {
		/* tests filtering */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(
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
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final UUID tokenID = UUID.randomUUID();
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("sometoken").thenReturn(null);
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000)).thenReturn(null);
		
		final TemporaryToken tt = auth.link("prov", "authcode");
		
		assertThat("incorrect temptoken", tt, is(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				set(storageRemoteID3, storageRemoteID4));
	}
	
	@Test
	public void linkWithoutTokenFailNullsAndEmpties() throws Exception {
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
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkWithoutToken(auth, null, "foo", new NullPointerException("provider"));
		failLinkWithoutToken(auth, "  \t ", "foo",
				new NoSuchIdentityProviderException("  \t "));
		failLinkWithoutToken(auth, "prov", null,
				new MissingParameterException("authorization code"));
		failLinkWithoutToken(auth, "prov", "  \n  ",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void linkWithoutTokenFailNoProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		failLinkWithoutToken(auth, "prov1", "foo",
				new NoSuchIdentityProviderException("prov1"));
	}
	
	@Test
	public void linkWithoutTokenFailNoProviderInConfig() throws Exception {
		/* this case indicates a programming error, a provider should never be in the internal
		 * Authorization class state but not in the config in the db
		 */
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"prov1", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkWithoutToken(auth, "prov", "foo",
				new NoSuchIdentityProviderException("Prov"));
	}
	
	@Test
	public void linkWithoutTokenFailDisabledProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(false, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		failLinkWithoutToken(auth, "prov", "foo",
				new NoSuchIdentityProviderException("prov"));
	}
	
	@Test
	public void linkWithoutTokenFailIDRetrievalFailed() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("Prov");
		
		final TestMocks testauth = initTestMocks(set(idp));
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final Map<String, ProviderConfig> providers = ImmutableMap.of(
				"Prov", new ProviderConfig(true, false, false));

		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(false, providers, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(idp.getIdentities("foo", true)).thenThrow(new IdentityRetrievalException("oh poop"));
		
		failLinkWithoutToken(auth, "prov", "foo", new IdentityRetrievalException("oh poop"));
	}
	
	private void failLinkWithoutToken(
			final Authentication auth,
			final String provider,
			final String authcode,
			final Exception e) {
		try {
			auth.link(provider, authcode);
			fail("exception expected");
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), Instant.now(),
						Instant.ofEpochMilli(20000),
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
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		final LinkIdentities li = auth.getLinkState(userToken, tempToken);
		
		assertThat("incorrect link identities", li, is(new LinkIdentities(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(10000))
				.withIdentity(REMOTE).build(),
				set(storageRemoteID3, storageRemoteID4),
				Instant.ofEpochMilli(20000))));
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
				new LinkFailedException("Cannot link identities to local accounts"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken()))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW,
						"errthing", ErrorType.ID_PROVIDER_ERROR))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW,
						"errthing", ErrorType.UNSUPPORTED_OP))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken,
				new RuntimeException("Unexpected error type UNSUPPORTED_OP"));
	}
	
	@Test
	public void getLinkStateFailNoIDs() throws Exception {
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW,
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")))))
				.thenReturn(null);
		
		final RemoteIdentity storageRemoteID2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));

		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		
		failGetLinkState(auth, userToken, tempToken,
				new LinkFailedException("All provided identities are already linked"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW,
						set(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
									new RemoteIdentityDetails("user2", "full2", "f2@g.com")),
							new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
									new RemoteIdentityDetails("user3", "full3", "f3@g.com")),
							new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
									new RemoteIdentityDetails("user4", "full4", "f4@g.com")))))
				.thenReturn(null);
		
		auth.link(userToken, tempToken, "de0702aa7927b562e0d6be5b6527cfb2");
		
		verify(storage).link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com")));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set()));
		
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
				new LinkFailedException("Cannot link identities to local accounts"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken()))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, 
						"errthing1", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new IdentityProviderErrorException("errthing1"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, 
						"errthing1", ErrorType.LINK_FAILED))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "f2@g.com")))))
				.thenReturn(null);
		
		failLinkIdentity(auth, userToken, tempToken, "fakeid",
				new LinkFailedException("Not authorized to link identity fakeid"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
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
		
		when(storage.getUser(storageRemoteID2)).thenReturn(Optional.of(AuthUser.getBuilder(
				new UserName("someuser"), new DisplayName("a"), Instant.now()).build()))
				.thenReturn(null);
		when(storage.getUser(storageRemoteID3)).thenReturn(Optional.absent())
				.thenReturn(null);
		when(storage.getUser(storageRemoteID4)).thenReturn(Optional.absent())
				.thenReturn(null);
		
		doThrow(new IdentityLinkedException("foo")).when(storage)
				.link(new UserName("baz"), storageRemoteID3);
		
		auth.linkAll(userToken, tempToken);
		
		verify(storage).link(new UserName("baz"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "f4@g.com")));
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
				new LinkFailedException("Cannot link identities to local accounts"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken()))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);

		final RemoteIdentity storageRemote3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		
		when(storage.getUser(storageRemote3)).thenReturn(Optional.absent());

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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, 
						"errthing3", ErrorType.ID_PROVIDER_ERROR))
				.thenReturn(null);

		failLinkAll(auth, userToken, tempToken, new IdentityProviderErrorException("errthing3"));
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, 
						"errthing3", ErrorType.NO_TOKEN))
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
		
		when(storage.getTemporaryIdentities(tempToken.getHashedToken())).thenReturn(
				new TemporaryIdentities(UUID.randomUUID(), NOW, NOW, set(
						new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
								new RemoteIdentityDetails("user3", "full3", "f3@g.com")))))
				.thenReturn(null);

		final RemoteIdentity storageRemote3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "f3@g.com"));
		
		when(storage.getUser(storageRemote3)).thenReturn(Optional.absent());

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
				new UnLinkFailedException("Local users don't have remote identities"));
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

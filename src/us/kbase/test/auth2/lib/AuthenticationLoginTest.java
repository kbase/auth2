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
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
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
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
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
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationLoginTest {
	
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(new RemoteIdentity(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeToken(new StoredToken(tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)),
				"rIWdQ6H23g7MLjLjJTz8k7A6zEbn6+Cnwm5anDwasLc=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		final LoginToken expected = new LoginToken(
				new NewToken(new StoredToken(tokenID, TokenType.LOGIN, null, new UserName("foo"),
						Instant.ofEpochMilli(20000),
						Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)), "thisisatoken"), 
				LoginState.getBuilder("prov", allowLogin).withUser(user, storageRemoteID).build());
		
		assertThat("incorrect login token", lt, is(expected));
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(new RemoteIdentity(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeIdentitiesTemporarily(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000).getHashedToken(),
				set(storageRemoteID));
		
		final LoginToken expected = new LoginToken(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000),
				LoginState.getBuilder("prov", allowLogin)
						.withUser(user.build(), storageRemoteID).build());
		
		assertThat("incorrect login token", lt, is(expected));
	}
	
	@Test
	public void storeUnlinkedIdentity() throws Exception {
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(new RemoteIdentity(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeIdentitiesTemporarily(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000).getHashedToken(),
				set(storageRemoteID));
		
		final LoginToken expected = new LoginToken(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000),
				LoginState.getBuilder("prov", true).withIdentity(storageRemoteID).build());
		
		assertThat("incorrect login token", lt, is(expected));
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(new RemoteIdentity(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeIdentitiesTemporarily(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000).getHashedToken(),
				set(storageRemoteID1, storageRemoteID2));
		
		final LoginToken expected = new LoginToken(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000),
				LoginState.getBuilder("prov", true).withIdentity(storageRemoteID1)
						.withUser(user, storageRemoteID2).build());
		
		assertThat("incorrect login token", lt, is(expected));
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeIdentitiesTemporarily(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000).getHashedToken(),
				set(storageRemoteID1, storageRemoteID2, storageRemoteID3));
		
		final LoginToken expected = new LoginToken(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000),
				LoginState.getBuilder("prov", true)
						.withUser(user, storageRemoteID1)
						.withUser(user, storageRemoteID2)
						.withUser(user2, storageRemoteID3)
						.build());
		
		assertThat("incorrect login token", lt, is(expected));
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
		
		when(idp.getIdentities("foobar", false)).thenReturn(set(
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
		
		final LoginToken lt = auth.login("prov", "foobar");
		
		verify(storage).storeIdentitiesTemporarily(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000).getHashedToken(),
				set(storageRemoteID1, storageRemoteID2, storageRemoteID3));
		
		final LoginToken expected = new LoginToken(
				new TemporaryToken(tokenID, "thisisatoken", Instant.ofEpochMilli(20000),
						30 * 60 * 1000),
				LoginState.getBuilder("prov", true)
						.withIdentity(storageRemoteID1)
						.withIdentity(storageRemoteID2)
						.withIdentity(storageRemoteID3)
						.build());
		
		assertThat("incorrect login token", lt, is(expected));
	}
	
	@Test
	public void failLoginNullsAndEmpties() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		failLogin(auth, null, "foo", new NullPointerException("provider"));
		failLogin(auth, "   \t  \n   ", "foo",
				new NoSuchIdentityProviderException("   \t  \n   "));
		failLogin(auth, "prov", null,
				new MissingParameterException("authorization code"));
		failLogin(auth, "prov", "    \t \n   ",
				new MissingParameterException("authorization code"));
	}
	
	@Test
	public void failLoginNoSuchProvider() throws Exception {
		final IdentityProvider idp = mock(IdentityProvider.class);

		when(idp.getProviderName()).thenReturn("prov");
		
		final Authentication auth = initTestMocks(set(idp)).auth;
		
		failLogin(auth, "prov1", "foo", new NoSuchIdentityProviderException("prov1"));
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
		
		failLogin(auth, "prov", "foo", new NoSuchIdentityProviderException("prov"));
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
		
		when(idp.getIdentities("foobar", false)).thenThrow(new IdentityRetrievalException("foo"));
		
		failLogin(auth, "prov", "foobar", new IdentityRetrievalException("foo"));
	}
	
	private void failLogin(
			final Authentication auth,
			final String provider,
			final String authcode,
			final Exception e) {
		try {
			auth.login(provider, authcode);
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
		
		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
				.thenReturn(Optional.absent());
		
		final LoginState got = auth.getLoginState(token);
		
		final LoginState expected = LoginState.getBuilder("prov", true)
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
	}
	
	@Test
	public void getLoginStateTwoUnlinkedIDsAndNoLoginAllowed() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		final LoginState expected = LoginState.getBuilder("prov", false)
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
	}
	
	@Test
	public void getLoginStateOneLinkedID() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		final LoginState expected = LoginState.getBuilder("prov", true)
				.withUser(AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
						Instant.ofEpochMilli(10000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
	}
	
	@Test
	public void getLoginStateTwoLinkedIDs() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		final LoginState expected = LoginState.getBuilder("prov", true).withUser(
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
						new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
	}
	
	@Test
	public void getLoginStateOneLinkedOneUnlinkedID() throws Exception {
		
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		final LoginState expected = LoginState.getBuilder("prov", true).withUser(
				AuthUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
						Instant.ofEpochMilli(10000L))
						.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
								new RemoteIdentityDetails("user1", "full1", "f@g.com"))).build(),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				
				.withIdentity(new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
						new RemoteIdentityDetails("user2", "full2", "e@g.com"))).build();
		
		assertThat("incorrect login state", got, is(expected));
	}
	
	@Test
	public void getLoginStateFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetLoginState(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getLoginStateFailInvalidToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failGetLoginState(auth, token, new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void getLoginStateFailNoIDs() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getTemporaryIdentities(token.getHashedToken()))
				.thenReturn(Collections.emptySet());
		
		failGetLoginState(auth, token, new RuntimeException(
				"Programming error: temporary login token stored with no identities"));
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

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				set(new PolicyID("pid1"), new PolicyID("pid2")), false);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withPolicyID(new PolicyID("pid1"), Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("pid2"), Instant.ofEpochMilli(10000)).build());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(new StoredToken(tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(20000L),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)), "mfingtoken")));
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

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				set(new PolicyID("pid1"), new PolicyID("pid2")), true);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withPolicyID(new PolicyID("pid1"), Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("pid2"), Instant.ofEpochMilli(10000)).build());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(new StoredToken( tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(20000L),
				Instant.ofEpochMilli(120000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000 + 100000)), "mfingtoken")));
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

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
							new RemoteIdentityDetails("user3", "full3", "d@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
							new RemoteIdentityDetails("user4", "full4", "c@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
							new RemoteIdentityDetails("user5", "full5", "b@g.com"))));
		
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
		doThrow(new IdentityLinkedException("foo")).when(storage).link(
				new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com")));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.createUser(token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				Collections.emptySet(), true);

		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")))
				.withEmailAddress(new EmailAddress("f@g.com")).build());
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")));
		
		verify(storage).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		verify(storage).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com")));
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com")));

		verify(storage).storeToken(new StoredToken( tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(20000L),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)), "mfingtoken")));
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
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, null, id, u, d, e, pids, l, new NullPointerException("token"));
		failCreateUser(auth, t, null, u, d, e, pids, l,
				new IllegalArgumentException("Missing argument: identityID"));
		failCreateUser(auth, t, "   \t   ", u, d, e, pids, l,
				new IllegalArgumentException("Missing argument: identityID"));
		failCreateUser(auth, t, id, null, d, e, pids, l, new NullPointerException("userName"));
		failCreateUser(auth, t, id, u, null, e, pids, l, new NullPointerException("displayName"));
		failCreateUser(auth, t, id, u, d, null, pids, l, new NullPointerException("email"));
		failCreateUser(auth, t, id, u, d, e, null, l, new NullPointerException("policyIDs"));
		failCreateUser(auth, t, id, u, d, e, set(new PolicyID("foo"), null), l,
				new NullPointerException("null item in policyIDs"));
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
				new InvalidTokenException("Temporary token"));
	}
	
	@Test
	public void createUserFailEmptyIdentities() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		final IncomingToken t = new IncomingToken("foo");

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(Collections.emptySet());
		
		final String id = "bar";
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
				new UnauthorizedException(ErrorType.UNAUTHORIZED,
						"Not authorized to create user with remote identity bar"));
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

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
		final String id = "bar"; //yep, that won't match
		final UserName u = new UserName("baz");
		final DisplayName d = new DisplayName("bat");
		final EmailAddress e = new EmailAddress("e@g.com");
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = true;
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l, new UserExistsException("baz"));
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

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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

		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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

		when(storage.getTemporaryIdentities(t.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l,
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

		when(storage.getTemporaryIdentities(t.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		failCreateUser(auth, t, id, u, d, e, pids, l, new RuntimeException(
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

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), Instant.ofEpochMilli(30000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		doThrow(new NoSuchUserException("foo")).when(storage).setLastLogin(
				new UserName("foo"), Instant.ofEpochMilli(30000));
		
		failCreateUser(auth, token, "ef0518c79af70ed979907969c6d0a0f7",
				new UserName("foo"), new DisplayName("bar"), new EmailAddress("f@g.com"),
				Collections.emptySet(), false, new AuthStorageException(
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
			final boolean linkAll,
			final Exception e) {
		try {
			auth.createUser(token, identityID, userName, displayName, email, pids, linkAll);
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
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
						new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
								new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
				set(new PolicyID("pid1"),  new PolicyID("pid2")), false);
		
		verify(storage).addPolicyIDs(new UserName("foo"),
				set(new PolicyID("pid1"), new PolicyID("pid2")));
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(new StoredToken(
				tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(10000 + 14 * 24 * 3600 * 1000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(10000),
				Instant.ofEpochMilli(10000 + 14 * 24 * 3600 * 1000)), "mfingtoken")));
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

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
				Collections.emptySet(), true);
		
		verify(storage, never()).addPolicyIDs(any(), any());
		
		verify(storage, never()).link(any(), any());
		
		verify(storage).storeToken(new StoredToken(tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(610000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(10000),
				Instant.ofEpochMilli(10000 + 600000)), "mfingtoken")));
	}
	
	@Test
	public void completeLoginAndLinkAll() throws Exception {
		/* also tests no policy ids case
		 * this is also friggin huge
		 */
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);

		final IncomingToken token = new IncomingToken("foobar");
		final UUID tokenID = UUID.randomUUID();

		when(storage.getTemporaryIdentities(token.getHashedToken())).thenReturn(
				set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
							new RemoteIdentityDetails("user3", "full3", "d@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id4"),
							new RemoteIdentityDetails("user4", "full4", "c@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id5"),
							new RemoteIdentityDetails("user5", "full5", "b@g.com"))));
		
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
		doThrow(new IdentityLinkedException("foo")).when(storage).link(
				new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id3"),
				new RemoteIdentityDetails("user3", "full3", "d@g.com")));
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSet<CollectingExternalConfig>(
						new AuthConfig(true, null, null),
						new CollectingExternalConfig(Collections.emptyMap())));
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(20000L), null);
		when(rand.randomUUID()).thenReturn(tokenID).thenReturn(null);
		when(rand.getToken()).thenReturn("mfingtoken");
		
		final NewToken nt = auth.login(token, "ef0518c79af70ed979907969c6d0a0f7",
				Collections.emptySet(), true);
		
		verify(storage, never()).addPolicyIDs(any(), any());
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com")));
		
		verify(storage).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "e@g.com")));
		
		verify(storage).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id4"),
				new RemoteIdentityDetails("user4", "full4", "c@g.com")));
		
		verify(storage, never()).link(new UserName("foo"), new RemoteIdentity(
				new RemoteIdentityID("prov", "id5"),
				new RemoteIdentityDetails("user5", "full5", "b@g.com")));
		
		verify(storage).storeToken(new StoredToken(tokenID, TokenType.LOGIN, null,
				new UserName("foo"), Instant.ofEpochMilli(10000L),
				Instant.ofEpochMilli(10000 + 14 * 24 * 3600 * 1000)),
				"hQ9Z3p0WaYunsmIBRUcJgBn5Pd4BCYhOEQCE3enFOzA=");
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(20000));
		
		assertThat("incorrect new token", nt, is(new NewToken(new StoredToken(
				tokenID, TokenType.LOGIN, null, new UserName("foo"),
				Instant.ofEpochMilli(10000),
				Instant.ofEpochMilli(10000 + 14 * 24 * 3600 * 1000)), "mfingtoken")));
	}
	
	@Test
	public void completeLoginFailNullsAndEmpties() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final String id = "whee";
		final Set<PolicyID> pids = Collections.emptySet();
		final boolean l = false;
		
		failCompleteLogin(auth, null, id, pids, l, new NullPointerException("token"));
		failCompleteLogin(auth, t, null, pids, l,
				new IllegalArgumentException("Missing argument: identityID"));
		failCompleteLogin(auth, t, "   \t   ", pids, l,
				new IllegalArgumentException("Missing argument: identityID"));
		failCompleteLogin(auth, t, id, null, l, new NullPointerException("policyIDs"));
		failCompleteLogin(auth, t, id, set(new PolicyID("foo"), null), l,
				new NullPointerException("null item in policyIDs"));
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failCompleteLogin(auth, t, id, pids, l, new InvalidTokenException("Temporary token"));
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
		failCompleteLogin(auth, t, id, pids, l, new UnauthorizedException(ErrorType.UNAUTHORIZED,
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
		when(storage.getUser(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
				new RemoteIdentityDetails("user1", "full1", "f@g.com"))))
					.thenReturn(Optional.absent());
		
		failCompleteLogin(auth, t, id, pids, l, new AuthenticationException(
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, "Non-admin login is disabled"));
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new DisabledUserException());
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new AuthStorageException(
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new AuthStorageException(
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com")),
					new RemoteIdentity(new RemoteIdentityID("prov", "id2"),
							new RemoteIdentityDetails("user2", "full2", "e@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new RuntimeException(
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
		
		when(storage.getTemporaryIdentities(t.getHashedToken()))
				.thenReturn(set(new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
						new RemoteIdentityDetails("user1", "full1", "f@g.com"))));
		
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
		
		failCompleteLogin(auth, t, id, pids, l, new AuthStorageException(
				"Something is very broken. User should exist but doesn't: " +
				"50000 No such user: foo"));
	}
	
	private void failCompleteLogin(
			final Authentication auth,
			final IncomingToken token,
			final String identityID,
			final Set<PolicyID> policyIDs,
			final boolean linkAll,
			final Exception e) {
		try {
			auth.login(token, identityID, policyIDs, linkAll);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

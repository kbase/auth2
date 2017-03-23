package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
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
		
		verify(storage).storeToken(new HashedToken(tokenID, TokenType.LOGIN, null,
				"rIWdQ6H23g7MLjLjJTz8k7A6zEbn6+Cnwm5anDwasLc=",
				new UserName("foo"), Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000 + 14 * 24 * 3600 * 1000)));
		
		verify(storage).setLastLogin(new UserName("foo"), Instant.ofEpochMilli(30000));
		
		final LoginToken expected = new LoginToken(
				new NewToken(tokenID, TokenType.LOGIN, "thisisatoken", new UserName("foo"),
						Instant.ofEpochMilli(20000), 14 * 24 * 3600 * 1000),
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
		final Authentication auth = initTestMocks().auth;
		
		failLogin(auth, null, "foo", new NullPointerException("provider"));
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
}

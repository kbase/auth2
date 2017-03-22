package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.Test;
import org.mockito.verification.VerificationMode;

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
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
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
		storeSingleIdentity(Role.DEV_TOKEN, false, false, false);
		storeSingleIdentity(Role.DEV_TOKEN, true, true, false);
		storeSingleIdentity(Role.ADMIN, true, false, false);
		storeSingleIdentity(Role.CREATE_ADMIN, true, false, false);
		storeSingleIdentity(Role.DEV_TOKEN, false, true, true);
		storeSingleIdentity(Role.ADMIN, false, false, true);
		storeSingleIdentity(Role.CREATE_ADMIN, false, false, true);
	}
	
	private void storeSingleIdentity(
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
}

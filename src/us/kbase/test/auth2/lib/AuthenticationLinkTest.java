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
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationLinkTest {
	
	private final RemoteIdentity REMOTE = new RemoteIdentity(new RemoteIdentityID("prov", "id1"),
			new RemoteIdentityDetails("user1", "full1", "f1@g.com"));
	
	@Test
	public void linkWithTokenImmediately() throws Exception {
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
						.withLifeTime(Instant.now(), Instant.now()).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("baz"))).thenReturn(AuthUser.getBuilder(
				new UserName("baz"), new DisplayName("foo"), Instant.now())
				.withIdentity(REMOTE).build()).thenReturn(null);
		
		when(idp.getIdentities("authcode", true)).thenReturn(set(new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"))))
				.thenReturn(null);

		final RemoteIdentity storageRemoteID = new RemoteIdentity(
				new RemoteIdentityID("prov", "id2"),
				new RemoteIdentityDetails("user2", "full2", "f2@g.com"));
		
		when(storage.getUser(storageRemoteID)).thenReturn(Optional.absent()).thenReturn(null);
		
		final LinkToken lt = auth.link(token, "prov", "authcode");
		
		assertThat("incorrect linktoken", lt, is(new LinkToken()));
		
		verify(storage).link(new UserName("baz"), storageRemoteID);
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
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000),
				new LinkIdentities(AuthUser.getBuilder(
						new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
						.withIdentity(REMOTE).build(),
						set(storageRemoteID)))));
		
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
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000),
				new LinkIdentities(AuthUser.getBuilder(
						new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
						.withIdentity(REMOTE).build(),
						"prov"))));
		
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
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000),
				new LinkIdentities(AuthUser.getBuilder(
						new UserName("baz"), new DisplayName("foo"), Instant.ofEpochMilli(20000))
						.withIdentity(REMOTE).build(),
						set(storageRemoteID3, storageRemoteID4)))));
		
		verify(storage).storeIdentitiesTemporarily(new TemporaryToken(
				tokenID, "sometoken", Instant.ofEpochMilli(10000), 10 * 60 * 1000)
						.getHashedToken(),
				set(storageRemoteID3, storageRemoteID4));
		
		verify(storage, never()).link(any(), any());
	}

}

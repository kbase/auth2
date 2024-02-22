package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;
import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationTokenTest {
	
	/* tests token get, create, and revoke. */
	
	private static final UUID UID = UUID.randomUUID();
	
	private static final TokenCreationContext CTX = TokenCreationContext.getBuilder().build();
	
	private static final StoredToken TOKEN1;
	private static final StoredToken TOKEN2;
	static {
		try {
			TOKEN1 = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
					.withLifeTime(Instant.ofEpochMilli(3000), 1000).build();
			TOKEN2 = StoredToken.getBuilder(
					TokenType.DEV, UUID.randomUUID(), new UserName("foo"))
					.withLifeTime(Instant.ofEpochMilli(5000), 1000)
					.withTokenName(new TokenName("baz")).build();
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests newb", e);
		}
	}
	
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
	public void getToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.DEV, id, new UserName("foo")).withLifeTime(now, now).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected);
		
		final StoredToken ht = auth.getToken(t);
		assertThat("incorrect token", ht, is(StoredToken.getBuilder(
				TokenType.DEV, id, new UserName("foo")).withLifeTime(now, now).build()));
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, 
				"User foo accessed DEV token " + id, Authentication.class));
	}
	
	@Test
	public void getTokenFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetToken(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void getTokenExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getToken(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get token";
			}
		}, set());
	}

	private void failGetToken(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.getToken(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokens() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo")).withLifeTime(now, now).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(expected, (StoredToken) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		final TokenSet ts = auth.getTokens(t);
		assertThat("incorrect token set", ts, is(new TokenSet(expected, set(TOKEN2, TOKEN1))));
		
		assertLogEventsCorrect(logEvents,
				new LogEvent(Level.INFO, "User foo accessed their tokens", Authentication.class));
	}
	
	@Test
	public void getTokensFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failGetTokens(auth, null, new NullPointerException("token"));
	}

	@Test
	public void getTokensExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getTokens(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get tokens";
			}
		});
	}
	
	private void failGetTokens(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.getTokens(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokensUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();
		
		getTokensUser(admin);
	}
	
	@Test
	public void getTokensUserExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.getTokens(token, new UserName("whee"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "get tokens for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void getTokensUserFailNulls() throws Exception {
		final TestMocks testauth = initTestMocks();
		final Authentication auth = testauth.auth;
		
		failGetTokensUser(auth, null, new UserName("foo"), new NullPointerException("token"));
		failGetTokensUser(auth, new IncomingToken("foo"), null,
				new NullPointerException("userName"));
	}
	
	private void getTokensUser(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobarbaz");
		final StoredToken token = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(token, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin, (AuthUser) null);
		
		when(storage.getTokens(new UserName("foo"))).thenReturn(set(TOKEN1, TOKEN2));
		
		try {
			final Set<StoredToken> tokens = auth.getTokens(t, new UserName("foo"));
			assertThat("incorrect tokens", tokens, is(set(TOKEN1, TOKEN2)));
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"Admin %s accessed user foo's tokens", admin.getUserName().getName()),
					Authentication.class));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failGetTokensUser(
			final Authentication auth,
			final IncomingToken token,
			final UserName name,
			final Exception e) {
		try {
			auth.getTokens(token, name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void logout() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		when(storage.deleteTemporarySessionData(new UserName("foo"))).thenReturn(42L);
		
		final Optional<StoredToken> res = auth.logout(t);
		
		verify(storage).deleteToken(new UserName("foo"), id);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User foo revoked token " + id + " and 42 temporary session instances",
				Authentication.class));
		
		assertThat("incorrect token", res, is(Optional.of(ht)));
	}
	
	@Test
	public void logoutNoToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		final Optional<StoredToken> res = auth.logout(t);
		
		assertThat("incorrect token", res, is(Optional.empty()));
		
		verify(storage, never()).deleteToken(any(), any());
		verify(storage, never()).deleteTemporarySessionData((UserName) any());
	}
	
	@Test
	public void logoutFail() throws Exception {
		final Authentication auth = initTestMocks().auth;
		try {
			auth.logout(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	@Test
	public void revokeSelf() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID id = UUID.randomUUID();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		final Optional<StoredToken> res = auth.revokeToken(t);
		
		verify(storage).deleteToken(new UserName("foo"), id);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User foo revoked token " + id, Authentication.class));
		
		assertThat("incorrect token", res, is(Optional.of(ht)));
	}
	
	@Test
	public void revokeSelfNoToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.getToken(t.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		final Optional<StoredToken> res = auth.revokeToken(t);
		
		verify(storage, never()).deleteToken(any(), any());
		
		assertThat("incorrect token", res, is(Optional.empty()));
	}
	
	@Test
	public void revokeSelfFail() throws Exception {
		final Authentication auth = initTestMocks().auth;
		try {
			auth.revokeToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	@Test
	public void revokeToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		final UUID id = UUID.randomUUID();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		auth.revokeToken(t, target);
		
		verify(storage).deleteToken(new UserName("foo"), target);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"User foo revoked token " + id, Authentication.class));
	}
	
	@Test
	public void revokeTokenExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		final UUID id = UUID.randomUUID();
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.revokeToken(token, id);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "revoke token " + id;
			}
		});
	}
	
	@Test
	public void revokeTokenFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		doThrow(new NoSuchTokenException(target.toString()))
			.when(storage).deleteToken(new UserName("foo"), target);
		
		failRevokeToken(auth, t, target, new NoSuchTokenException(target.toString()));
	}
	
	@Test
	public void revokeTokenFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeToken(auth, null, UUID.randomUUID(), new NullPointerException("token"));
		failRevokeToken(auth, new IncomingToken("f"), null, new NullPointerException("tokenID"));
	}
	
	private void failRevokeToken(
			final Authentication auth,
			final IncomingToken t,
			final UUID target,
			final Exception e) {
		try {
			auth.revokeToken(t, target);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeTokenAdmin() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();

		revokeTokenAdmin(admin);
	}
	
	@Test
	public void revokeTokenAdminExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		final UUID id = UUID.randomUUID();
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.revokeToken(token, new UserName("whee"), id);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "revoke token " + id + " for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void revokeTokenAdminFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeTokenAdmin(auth, null, new UserName("foo"), UUID.randomUUID(),
				new NullPointerException("token"));
		failRevokeTokenAdmin(auth, new IncomingToken("f"), null, UUID.randomUUID(),
				new NullPointerException("userName"));
		failRevokeTokenAdmin(auth, new IncomingToken("f"), new UserName("foo"), null,
				new NullPointerException("tokenID"));
	}
	
	@Test
	public void revokeTokenAdminFailNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final UUID target = UUID.randomUUID();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(admin);
		
		doThrow(new NoSuchTokenException(target.toString()))
				.when(storage).deleteToken(new UserName("bar"), target);
		
		failRevokeTokenAdmin(auth, t, new UserName("bar"), target,
				new NoSuchTokenException(target.toString()));
	}

	private void revokeTokenAdmin(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		final UUID target = UUID.randomUUID();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeToken(t, new UserName("whee"), target);
		
			verify(storage).deleteToken(new UserName("whee"), target);
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"Admin %s revoked user whee's token %s",
					admin.getUserName().getName(), target), Authentication.class));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeTokenAdmin(
			final Authentication auth,
			final IncomingToken t,
			final UserName name,
			final UUID target,
			final Exception e) {
		try {
			auth.revokeToken(t, name, target);
			fail("exception expected");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeAllTokensUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		auth.revokeTokens(t);
		
		verify(storage).deleteTokens(new UserName("foo"));
		
		assertLogEventsCorrect(logEvents, new LogEvent(
				Level.INFO, "User foo revoked all their tokens", Authentication.class));
	}
	
	@Test
	public void revokeAllTokensUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensUser(auth, null, new NullPointerException("token"));
	}
	
	@Test
	public void revokeAllTokensUserExecuteStandardTokenCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardTokenCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.revokeTokens(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "revoke owned tokens";
			}
		});
	}
	
	private void failRevokeAllTokensUser(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.revokeTokens(t);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

	@Test
	public void revokeAllTokensAdminAll() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();
		
		revokeAllTokensAdminAll(admin);
	}
	
	@Test
	public void revokeAllTokensAdminAllExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.revokeAllTokens(token);
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "revoke all tokens";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void revokeAllTokensAdminAllFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensAdminAll(auth, null, new NullPointerException("token"));
	}
	
	private void revokeAllTokensAdminAll(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeAllTokens(t);
		
			verify(storage).deleteTokens();
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"Admin %s revoked all tokens system wide", admin.getUserName().getName()),
					Authentication.class));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeAllTokensAdminAll(
			final Authentication auth,
			final IncomingToken t,
			final Exception e) {
		try {
			auth.revokeAllTokens(t);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void revokeAllTokensAdminUser() throws Exception {
		final AuthUser admin = AuthUser.getBuilder(
				new UserName("admin"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();
		
		revokeAllTokensAdminUser(admin);
	}
	
	@Test
	public void revokeAllTokensAdminUserExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.revokeAllTokens(token, new UserName("whee"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "revoke all tokens for user whee";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void revokeAllTokensAdminUserFailNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRevokeAllTokensAdminUser(auth, null, new UserName("foo"),
				new NullPointerException("token"));
		failRevokeAllTokensAdminUser(auth, new IncomingToken("f"), null,
				new NullPointerException("userName"));
	}
	
	
	private void revokeAllTokensAdminUser(final AuthUser admin) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), admin.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(admin.getUserName())).thenReturn(admin);
		
		try {
			auth.revokeAllTokens(t, new UserName("whee"));
		
			verify(storage).deleteTokens(new UserName("whee"));
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"Admin %s revoked all tokens for user whee", admin.getUserName().getName()),
					Authentication.class));
		} catch (Throwable th) {
			if (admin.isDisabled()) {
				verify(storage).deleteTokens(admin.getUserName());
			}
			throw th;
		}
	}
	
	private void failRevokeAllTokensAdminUser(
			final Authentication auth,
			final IncomingToken t,
			final UserName name,
			final Exception e) {
		try {
			auth.revokeAllTokens(t, name);
			fail("expected exceptoin");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void createAgentToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.build();
		
		createToken(user, new HashMap<>(), 7 * 24 * 3600 * 1000L, TokenType.AGENT);
	}
	
	@Test
	public void createAgentTokenWithAltLifeTime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.AGENT, 3 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 3 * 24 * 3600 * 1000L, TokenType.AGENT);
	}
	
	@Test
	public void createDevToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.DEV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 90 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createDevTokenAltLifetime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.DEV_TOKEN).build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.DEV, 42 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 42 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createDevTokenWithServRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 90 * 24 * 3600 * 1000L, TokenType.DEV);
	}
	
	@Test
	public void createServToken() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		createToken(user, new HashMap<>(), 100_000_000L * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createServTokenWithAdminRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.ADMIN).build();
		
		createToken(user, new HashMap<>(), 100_000_000L * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createServTokenWithAltLifetime() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.SERV_TOKEN).build();
		
		final HashMap<TokenLifetimeType, Long> lifetimes = new HashMap<>();
		lifetimes.put(TokenLifetimeType.SERV, 24 * 24 * 3600 * 1000L);
		createToken(user, lifetimes, 24 * 24 * 3600 * 1000L, TokenType.SERV);
	}
	
	@Test
	public void createTokenFailExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.createToken(token, new TokenName("foo"), TokenType.AGENT,
						TokenCreationContext.getBuilder().build());
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "create Agent token";
			}
		}, set());
	}
	
	@Test
	public void createTokenFailNoDevRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.CREATE_ADMIN).build();
		
		failCreateToken(user, TokenType.DEV, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"User foo is not authorized to create the Developer token type."));
	}
	
	@Test
	public void createTokenFailNoServRole() throws Exception {
		final AuthUser user = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), Instant.now())
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.DEV_TOKEN)
				.withRole(Role.CREATE_ADMIN).build();
		
		failCreateToken(user, TokenType.SERV, new UnauthorizedException(ErrorType.UNAUTHORIZED,
				"User foo is not authorized to create the Service token type."));
	}
	
	@Test
	public void createTokenFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failCreateToken(auth, null, new TokenName("foo"), TokenType.DEV, CTX,
				new NullPointerException("token"));
		failCreateToken(auth, new IncomingToken("foo"), null, TokenType.DEV, CTX,
				new NullPointerException("tokenName"));
		failCreateToken(auth, new IncomingToken("foo"), new TokenName("bar"), null, CTX,
				new NullPointerException("tokenType"));
		failCreateToken(auth, new IncomingToken("foo"), new TokenName("bar"), TokenType.DEV, null,
				new NullPointerException("tokenCtx"));
	}
	
	@Test
	public void createTokenFailCreateLogin() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failCreateToken(auth, new IncomingToken("foo"), new TokenName("bar"), TokenType.LOGIN, CTX,
				new IllegalArgumentException(
						"Cannot create a login token without logging in"));
	}
	
	private void createToken(
			final AuthUser user,
			final Map<TokenLifetimeType, Long> lifetimes,
			final long expectedLifetime,
			final TokenType tokenType) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		final Clock clock = testauth.clockMock;
		final RandomDataGenerator rand = testauth.randGenMock;
		
		AuthenticationTester.setConfigUpdateInterval(auth, -1);
		
		final IncomingToken t = new IncomingToken("foobar");
		final UUID id = UUID.randomUUID();
		final Instant time = Instant.ofEpochMilli(100000);
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), user.getUserName())
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		when(storage.getToken(t.getHashedToken())).thenReturn(ht, (StoredToken) null);
		
		when(storage.getUser(user.getUserName())).thenReturn(user, (AuthUser) null);
		
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(new AuthConfig(true, null, lifetimes),
						new CollectingExternalConfig(new HashMap<>())));
		
		when(rand.randomUUID()).thenReturn(id, (UUID) null);
		when(rand.getToken()).thenReturn("this is a token", (String)null);
		when(clock.instant()).thenReturn(time, (Instant) null);
		
		try {
			final NewToken nt = auth.createToken(t, new TokenName("a name"), tokenType,
					TokenCreationContext.getBuilder().withNullableDevice("device").build());
			
			final Instant expiration = Instant.ofEpochMilli(time.toEpochMilli() +
					(expectedLifetime));
			
			verify(storage).storeToken(StoredToken.getBuilder(tokenType, id, user.getUserName())
					.withLifeTime(time, expiration)
					.withTokenName(new TokenName("a name"))
					.withContext(TokenCreationContext.getBuilder()
							.withNullableDevice("device").build()).build(),
					"p40z9I2zpElkQqSkhbW6KG3jSgMRFr3ummqjSe7OzOc=");
			
			assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO, String.format(
					"User %s created %s token %s", user.getUserName().getName(), tokenType, id),
					Authentication.class));
			
			final NewToken expected = new NewToken(
					StoredToken.getBuilder(tokenType, id, user.getUserName())
							.withLifeTime(time, time.plusMillis(expectedLifetime))
							.withTokenName(new TokenName("a name"))
							.withContext(TokenCreationContext.getBuilder()
									.withNullableDevice("device").build()).build(),
					"this is a token");
			
			assertThat("incorrect token", nt, is(expected));
		} catch (Throwable th) {
			if (user.isDisabled()) {
				verify(storage).deleteTokens(user.getUserName());
			}
			throw th;
		}
	}
	
	private void failCreateToken(
			final AuthUser user,
			final TokenType tokenType,
			final Exception e) {
		try {
			createToken(user, new HashMap<>(), 3L, tokenType);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCreateToken(
			final Authentication auth,
			final IncomingToken t,
			final TokenName name,
			final TokenType tokenType,
			final TokenCreationContext ctx,
			final Exception e) {
		try {
			auth.createToken(t, name, tokenType, ctx);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void deleteLoginOrLinkState() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final UUID id = UUID.randomUUID();
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.deleteTemporarySessionData(new IncomingToken("foobar").getHashedToken()))
				.thenReturn(Optional.of(id));
		
		auth.deleteLinkOrLoginState(t);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Deleted temporary token " + id, Authentication.class));
	}
	
	@Test
	public void deleteLoginOrLinkStateNoSuchToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		
		when(storage.deleteTemporarySessionData(new IncomingToken("foobar").getHashedToken()))
				.thenReturn(Optional.empty());
		
		auth.deleteLinkOrLoginState(t);
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Attempted to delete non-existant temporary token", Authentication.class));
	}
	
	@Test
	public void deleteLoginOrLinkStateNull() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		try {
			auth.deleteLinkOrLoginState(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
}

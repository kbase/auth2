package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.spi.ILoggingEvent;
import jersey.repackaged.com.google.common.collect.ImmutableMap;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationAnonymousIDsTest {
	
	private static final UUID UID1 = UUID.randomUUID();
	private static final UUID UID2 = UUID.randomUUID();
	private static final Instant NOW = Instant.now();
	
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
	public void getUserNamesFromAnonymousIDsEmptyInput() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		when(storage.getUser(new UserName("admin"))).thenReturn(AuthUser.getBuilder(
				new UserName("admin"), UUID.randomUUID(), new DisplayName("d"), NOW)
				.withRole(Role.ADMIN)
				.build());
		
		final Map<UUID, UserName> ret = auth.getUserNamesFromAnonymousIDs(token, set());
		
		assertThat("incorrect user map", ret, is(Collections.emptyMap()));
	}
	
	@Test
	public void getUserNamesFromAnonymousIDs() throws Exception {
		// includes test of removing root user
		// includes test that dev tokens work
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<UUID, UserName> expected = ImmutableMap.of(
				UID1, new UserName("foo"), UID2, new UserName("bar"));

		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.DEV, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		when(storage.getUser(new UserName("admin"))).thenReturn(AuthUser.getBuilder(
				new UserName("admin"), UUID.randomUUID(), new DisplayName("d"), NOW)
				.withRole(Role.ADMIN)
				.build());
		final Map<UUID, UserName> mockret = new HashMap<>(); // needs to be mutable
		final UUID uid3 = UUID.randomUUID();
		mockret.put(UID1, new UserName("foo"));
		mockret.put(UID2, new UserName("bar"));
		mockret.put(uid3, new UserName("***ROOT***"));
		when(storage.getUserNamesFromAnonymousIDs(set(UID2, UID1, uid3))).thenReturn(mockret);
		
		final Map<UUID, UserName> ret = auth.getUserNamesFromAnonymousIDs(token, set(
				UID1, UID2, uid3));
		
		assertThat("incorrect user map", ret, is(expected));
	}
	
	@Test
	public void getUserNamesFromAnonymousIDsFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		final IncomingToken t = new IncomingToken("foobar");
		final Set<UUID> u = set(UID1);
		
		getUserNamesFromAnonymousIDsFail(auth, null, u, new NullPointerException("token"));
		getUserNamesFromAnonymousIDsFail(auth, t, null, new NullPointerException("anonymousIDs"));
		getUserNamesFromAnonymousIDsFail(auth, t, set(UID1, null), new NullPointerException(
				"Null ID in anonymousIDs"));
	}
	
	@Test
	public void getUserNamesFromAnonymousIDsExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(
				new AbstractAuthOperation() {
			
					@Override
					public IncomingToken getIncomingToken() {
						return token;
					}
					
					@Override
					public void execute(final Authentication auth) throws Exception {
						auth.getUserNamesFromAnonymousIDs(token, set(UID1));
					}
		
					@Override
					public List<ILoggingEvent> getLogAccumulator() {
						return logEvents;
					}
					
					@Override
					public String getOperationString() {
						return "translate anonymous IDs";
					}
				},
				set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT),
				set()
		);
	}
	
	@Test
	public void getUserNameFromAnonymousIDsFailTooManyInputs() throws Exception {
		// includes test that serv tokens work
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Set<UUID> inputs = Stream.generate(UUID::randomUUID)
				.limit(10001).collect(Collectors.toSet());
		
		when(storage.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.SERV, UUID.randomUUID(), new UserName("admin"))
						.withLifeTime(Instant.now(), Instant.now()).build());
		when(storage.getUser(new UserName("admin"))).thenReturn(AuthUser.getBuilder(
				new UserName("admin"), UUID.randomUUID(), new DisplayName("d"), NOW)
				.withRole(Role.ADMIN)
				.build());
		
		getUserNamesFromAnonymousIDsFail(auth, token, inputs, new IllegalParameterException(
				"Anonymous ID count exceeds maximum of 10000"));
	}
	
	private void getUserNamesFromAnonymousIDsFail(
			final Authentication auth,
			final IncomingToken token,
			final Set<UUID> anonymousIDs,
			final Exception expected) {
		try {
			auth.getUserNamesFromAnonymousIDs(token, anonymousIDs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}

}

package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.CollectingExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.config.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.AuthUser.Builder;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.config.TestExternalConfig;

public class AuthenticationTester {
	
	public static final TestExternalConfig<Action> TEST_EXTERNAL_CONFIG =
			new TestExternalConfig<>(ConfigItem.set("foo"));

	public static class TestMocks {
		final AuthStorage storageMock;
		final RandomDataGenerator randGenMock;
		final Authentication auth;
		final Clock clockMock;
		
		public TestMocks(
				final AuthStorage storageMock,
				final RandomDataGenerator randGenMock,
				final Authentication auth, // not a mock
				final Clock clockMock) {
			this.storageMock = storageMock;
			this.randGenMock = randGenMock;
			this.auth = auth;
			this.clockMock = clockMock;
		}
	}
	
	public static TestMocks initTestMocks() throws Exception {
		return initTestMocks(Collections.emptySet());
	}
	
	public static TestMocks initTestMocks(final Set<IdentityProvider> providers) throws Exception {
		return initTestMocks(providers, false);
	}
	
	public static TestMocks initTestMocks(final boolean testMode) throws Exception {
		return initTestMocks(Collections.emptySet(), testMode);
	}
	
	public static TestMocks initTestMocks(
			final Set<IdentityProvider> providers,
			final boolean testMode)
			throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final RandomDataGenerator randGen = mock(RandomDataGenerator.class);
		final Clock clock = mock(Clock.class);
		
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac, new CollectingExternalConfig(
						ImmutableMap.of("thing", ConfigItem.state("foo")))));
		
		final Constructor<Authentication> c = Authentication.class.getDeclaredConstructor(
				AuthStorage.class, Set.class, ExternalConfig.class, boolean.class,
				RandomDataGenerator.class, Clock.class);
		c.setAccessible(true);
		final Authentication instance = c.newInstance(storage, providers,
				TEST_EXTERNAL_CONFIG, testMode, randGen, clock);
		reset(storage);
		return new TestMocks(storage, randGen, instance, clock);
	}
	
	public static void setConfigUpdateInterval(final Authentication auth, final int millis)
			throws Exception {
		final Method method = auth.getClass().getDeclaredMethod(
				"setConfigUpdateInterval", int.class);
		method.setAccessible(true);
		method.invoke(auth, millis);
	}
	
	/* Match a LocalUser.
	 * The references to the user's password hash and salt are saved so that tests can check
	 * the data is cleared in the creation method.
	 */
	public static class LocalUserAnswerMatcher implements Answer<Void> {

		private final LocalUser user;
		public byte[] savedSalt;
		public byte[] savedHash;
		public byte[] expectedHash;
		public byte[] expectedSalt;
		
		public LocalUserAnswerMatcher(final LocalUser user, final PasswordHashAndSalt creds) {
			this.user = user;
			this.expectedHash = creds.getPasswordHash();
			this.expectedSalt = creds.getSalt();
		}
		
		@Override
		public Void answer(final InvocationOnMock inv) throws Throwable {
			final LocalUser user = inv.getArgument(0);
			final PasswordHashAndSalt creds = inv.getArgument(1);
			savedHash = creds.getPasswordHash();
			savedSalt = creds.getSalt();

			assertThat("local user does not match.", user, is(this.user));
			assertThat("password hash does not match", savedHash, is(expectedHash));
			assertThat("salt does not match", savedSalt, is(expectedSalt));
			return null;
		}
	}

	public static class ChangePasswordAnswerMatcher implements Answer<Void> {
		
		private final UserName name;
		private final byte[] hash;
		private final byte[] salt;
		private final boolean forceReset;
		public byte[] savedSalt;
		public byte[] savedHash;
		
		public ChangePasswordAnswerMatcher(
				final UserName name,
				final byte[] hash,
				final byte[] salt,
				final boolean forceReset) {
			this.name = name;
			this.hash = hash;
			this.salt = salt;
			this.forceReset = forceReset;
		}

		@Override
		public Void answer(final InvocationOnMock args) throws Throwable {
			final UserName un = args.getArgument(0);
			final PasswordHashAndSalt creds = args.getArgument(1);
			savedHash = creds.getPasswordHash();
			savedSalt = creds.getSalt();
			final boolean forceReset = args.getArgument(2);
			
			assertThat("incorrect username", un, is(name));
			assertThat("incorrect forcereset", forceReset, is(this.forceReset));
			assertThat("incorrect hash", savedHash, is(hash));
			assertThat("incorrect salt", savedSalt, is(salt));
			return null;
		}
	}
	
	public static String toBase64(final byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	public static byte[] fromBase64(final String base64) {
		return Base64.getDecoder().decode(base64);
	}
	
	public static class LogEvent {
		
		public final Level level;
		public final String message;
		public final Class<?> clazz;
		
		public LogEvent(Level level, String message, Class<?> clazz) {
			this.level = level;
			this.message = message;
			this.clazz = clazz;
		}
	}
	
	public static List<ILoggingEvent> setUpSLF4JTestLoggerAppender() {
		final Logger authRootLogger = (Logger) LoggerFactory.getLogger("us.kbase.auth2");
		authRootLogger.setAdditive(false);
		authRootLogger.setLevel(Level.ALL);
		final List<ILoggingEvent> logEvents = new LinkedList<>();
		final AppenderBase<ILoggingEvent> appender =
				new AppenderBase<ILoggingEvent>() {
			@Override
			protected void append(final ILoggingEvent event) {
				logEvents.add(event);
			}
		};
		appender.start();
		authRootLogger.addAppender(appender);
		return logEvents;
	}
	
	public static void assertLogEventsCorrect(
			final List<ILoggingEvent> logEvents,
			final LogEvent... expectedlogEvents) {
		
		assertThat("incorrect log event count for list: " + logEvents, logEvents.size(),
				is(expectedlogEvents.length));
		final Iterator<ILoggingEvent> iter = logEvents.iterator();
		for (final LogEvent le: expectedlogEvents) {
			final ILoggingEvent e = iter.next();
			assertThat("incorrect log level", e.getLevel(), is(le.level));
			assertThat("incorrect originating class", e.getLoggerName(), is(le.clazz.getName()));
			assertThat("incorrect message", e.getFormattedMessage(), is(le.message));
		}
	}
	
	public interface AuthOperation {
		public void execute(final Authentication auth) throws Exception;
		public IncomingToken getIncomingToken();
		public List<ILoggingEvent> getLogAccumulator();
		public String getOperationString();
		public TestMocks getTestMocks() throws Exception ;
	}
	
	public static abstract class AbstractAuthOperation implements AuthOperation {
		
		@Override
		public IncomingToken getIncomingToken() {
			try {
				return new IncomingToken("foobar");
			} catch (MissingParameterException e) {
				throw new RuntimeException("wtf dude", e);
			}
		}
		
		@Override
		public TestMocks getTestMocks() throws Exception {
			return initTestMocks();
		}
		
	}

	private static void failExecute(
			final AuthOperation ao,
			final Authentication auth,
			final String testName,
			final Exception e) {
		try {
			ao.execute(auth);
			fail("expected exception on " + testName);
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	public static Set<TokenType> DEFAULT_FAILING_TOKEN_TYPES = Collections.unmodifiableSet(
			set(TokenType.AGENT, TokenType.DEV, TokenType.SERV));
	
	public static void executeStandardUserCheckingTests(
			final AuthOperation ao,
			final Set<Role> failingRoles) throws Exception {
		executeStandardUserCheckingTests(ao, failingRoles, DEFAULT_FAILING_TOKEN_TYPES);
	}
	
	private static final TreeSet<Role> ALL_ROLES = new TreeSet<>();
	static {
		for (final Role r: Role.values()) {
			ALL_ROLES.add(r);
		}
	}
	
	public static void executeStandardUserCheckingTests(
			final AuthOperation ao,
			final Set<Role> failingRoles,
			final Set<TokenType> failingTypes) throws Exception {
		executeStandardTokenCheckingTests(ao, failingTypes);
		testNoUserForToken(ao);
		testDisabledUser(ao);
		@SuppressWarnings("unchecked")
		final Set<Role> allRoles = (Set<Role>) ALL_ROLES.clone();
		allRoles.removeAll(failingRoles);
		final String roleString = String.join(", ", allRoles.stream().map(r -> r.getID())
				.collect(Collectors.toList()));
		
		for (final Role r: failingRoles) {
			testUnauthorizedRole(ao, r, roleString);
		}
		if (!failingRoles.isEmpty()) {
			testUserWithoutRoles(ao, roleString);
		}
	}
	
	public static void executeStandardTokenCheckingTests(final AuthOperation ao) throws Exception {
		executeStandardTokenCheckingTests(ao, DEFAULT_FAILING_TOKEN_TYPES);
	}
	
	public static void executeStandardTokenCheckingTests(
			final AuthOperation ao,
			final Set<TokenType> failingTypes)
			throws Exception {
		testBadToken(ao);
		for (final TokenType tt: failingTypes) {
			testBadTokenType(ao, tt);
		}
	}

	private static void testBadToken(final AuthOperation ao) throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken()))
				.thenThrow(new NoSuchTokenException("foo"));
		
		failExecute(ao, auth, "bad token test", new InvalidTokenException());
	}

	private static void testBadTokenType(
			final AuthOperation ao,
			final TokenType type)
			throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		ao.getLogAccumulator().clear();
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken())).thenReturn(
				StoredToken.getBuilder(type, UUID.randomUUID(), new UserName("f"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);

		
		final String tokenName = type.getDescription();
		failExecute(ao, auth, "bad token type test: " + tokenName, new UnauthorizedException(
				ErrorType.UNAUTHORIZED, tokenName +
				" tokens are not allowed for this operation"));
		
		assertLogEventsCorrect(ao.getLogAccumulator(), new LogEvent(Level.ERROR, String.format(
				"User f with token type %s attempted an operation that requires a " +
				"token type of one of [Login]: " + ao.getOperationString(), tokenName),
						Authentication.class));
	}
	
	private static void testNoUserForToken(final AuthOperation ao) throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenThrow(new NoSuchUserException("foo"));
		
		failExecute(ao, auth, "no user for token test", new RuntimeException(
				"There seems to be an error in the storage system. " +
				"Token was valid, but no user"));
	}
	
	private static void testDisabledUser(final AuthOperation ao) throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now())
				.withUserDisabledState(
						new UserDisabledState("f", new UserName("b"), Instant.now())).build());
		
		failExecute(ao, auth, "disabled user test", new DisabledUserException("foo"));
		
		verify(storage).deleteTokens(new UserName("foo"));
	}
	
	private static void testUnauthorizedRole(
			final AuthOperation ao,
			final Role r,
			final String roleString)
			throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		ao.getLogAccumulator().clear();
		
		final UserName un;
		if (Role.ROOT.equals(r)) {
			un = UserName.ROOT;
		} else {
			un = new UserName("foo");
		}
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), un)
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(un)).thenReturn(AuthUser.getBuilder(
				un, new DisplayName("f"), Instant.now())
				.withRole(r).build());
		
		failExecute(ao, auth, "unauthorized user test for role " + r,
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		
		assertLogEventsCorrect(ao.getLogAccumulator(), new LogEvent(Level.ERROR, String.format(
				"User %s does not have one of the required roles [%s] for operation " +
						ao.getOperationString(), un.getName(), roleString),
						Authentication.class));
	}
	
	private static void testUserWithoutRoles(final AuthOperation ao, final String roleString)
			throws Exception {
		final TestMocks testauth = ao.getTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		ao.getLogAccumulator().clear();
		
		when(storage.getToken(ao.getIncomingToken().getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		when(storage.getUser(new UserName("foo"))).thenReturn(AuthUser.getBuilder(
				new UserName("foo"), new DisplayName("f"), Instant.now()).build());
		
		failExecute(ao, auth, "unauthorized user test",
				new UnauthorizedException(ErrorType.UNAUTHORIZED));
		
		assertLogEventsCorrect(ao.getLogAccumulator(), new LogEvent(Level.ERROR, String.format(
				"User foo does not have one of the required roles [%s] for operation " +
						ao.getOperationString(), roleString),
						Authentication.class));
	}
	
	public static void setupValidUserResponses(
			final AuthStorage storageMock,
			final UserName userName,
			final Role role,
			final IncomingToken token)
			throws Exception {
		
		when(storageMock.getToken(token.getHashedToken())).thenReturn(
				StoredToken.getBuilder(TokenType.LOGIN, UUID.randomUUID(), userName)
						.withLifeTime(Instant.now(), 0).build())
				.thenReturn(null);
		
		final Builder builder = AuthUser.getBuilder(
				userName, new DisplayName("f"), Instant.now());
		
		if (role != null) {
			builder.withRole(role);
		}
		when(storageMock.getUser(userName)).thenReturn(builder.build());
		
	}
}

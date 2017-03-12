package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.time.Clock;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.storage.AuthStorage;

public class AuthenticationTester {
	
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
		final AuthStorage storage = mock(AuthStorage.class);
		final RandomDataGenerator randGen = mock(RandomDataGenerator.class);
		final Clock clock = mock(Clock.class);
		
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		final Constructor<Authentication> c = Authentication.class.getDeclaredConstructor(
				AuthStorage.class, Set.class, ExternalConfig.class,
				RandomDataGenerator.class, Clock.class);
		c.setAccessible(true);
		final Authentication instance = c.newInstance(storage, Collections.emptySet(),
				new TestExternalConfig("foo"), randGen, clock);
		reset(storage);
		return new TestMocks(storage, randGen, instance, clock);
	}
	
	public static void setConfigUpdateInterval(final Authentication auth, final int sec)
			throws Exception {
		final Method method = auth.getClass().getDeclaredMethod(
				"setConfigUpdateInterval", int.class);
		method.setAccessible(true);
		method.invoke(auth, sec);
	}
	
	/* Match a LocalUser.
	 * The references to the user's password hash and salt are saved so that tests can check
	 * the data is cleared in the creation method.
	 */
	public static class LocalUserAnswerMatcher<T extends LocalUser> implements Answer<Void> {

		private final T user;
		public byte[] savedSalt;
		public byte[] savedHash;
		
		
		public LocalUserAnswerMatcher(final T user) {
			this.user = user;
		}
		
		@Override
		public Void answer(final InvocationOnMock inv) throws Throwable {
			final T user = inv.getArgument(0);
			savedSalt = user.getSalt();
			savedHash = user.getPasswordHash();

			assertThat("local user does not match.", user, is(this.user));
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
			savedHash = args.getArgument(1);
			savedSalt = args.getArgument(2);
			final boolean forceReset = args.getArgument(3);
			
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
	
}

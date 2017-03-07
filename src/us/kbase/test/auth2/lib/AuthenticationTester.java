package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
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
import us.kbase.auth2.lib.storage.AuthStorage;

public class AuthenticationTester {
	
	public static class TestAuth {
		final AuthStorage storageMock;
		final RandomDataGenerator randGen;
		final Authentication auth;
		final Clock clock;
		
		public TestAuth(
				final AuthStorage storageMock,
				final RandomDataGenerator randGen,
				final Authentication auth,
				final Clock clock) {
			this.storageMock = storageMock;
			this.randGen = randGen;
			this.auth = auth;
			this.clock = clock;
		}
	}
	
	public static TestAuth initTestAuth() throws Exception {
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
		return new TestAuth(storage, randGen, instance, clock);
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
	
	public static String toBase64(final byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	public static byte[] fromBase64(final String base64) {
		return Base64.getDecoder().decode(base64);
		
	}
	
}

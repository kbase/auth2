package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.cryptutils.RandomDataGenerator;
import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CollectingExternalConfig;
import us.kbase.auth2.lib.CollectingExternalConfig.CollectingExternalConfigMapper;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.test.auth2.TestCommon;

public class AuthenticationTester {
	
	public static class TestAuth {
		final AuthStorage storageMock;
		final RandomDataGenerator randGen;
		final Authentication auth;
		
		public TestAuth(
				final AuthStorage storageMock,
				final RandomDataGenerator randGen,
				final Authentication auth) {
			this.storageMock = storageMock;
			this.randGen = randGen;
			this.auth = auth;
		}
	}
	
	public static TestAuth initTestAuth() throws Exception {
		final AuthStorage storage = mock(AuthStorage.class);
		final RandomDataGenerator randGen = mock(RandomDataGenerator.class);
		final AuthConfig ac =  new AuthConfig(AuthConfig.DEFAULT_LOGIN_ALLOWED, null,
				AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS);
		when(storage.getConfig(isA(CollectingExternalConfigMapper.class))).thenReturn(
				new AuthConfigSet<>(ac,
						new CollectingExternalConfig(ImmutableMap.of("thing", "foo"))));
		
		final Constructor<Authentication> c = Authentication.class.getDeclaredConstructor(
				AuthStorage.class, Set.class, ExternalConfig.class,
				RandomDataGenerator.class);
		c.setAccessible(true);
		final Authentication instance = c.newInstance(storage, Collections.emptySet(),
				new TestExternalConfig("foo"), randGen);
		return new TestAuth(storage, randGen, instance);
	}
	
	/* Match a LocalUser.
	 * The references to the user's password hash and salt are saved so that tests can check
	 * the data is cleared in the creation method.
	 * The created date in the provided user is ignored.
	 * The created date on the new user is checked to be within 1 s of the current time.
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

			/* omg you bad person */
			final Field f = AuthUser.class.getDeclaredField("created");
			f.setAccessible(true);
			f.set(user, this.user.getCreated().getTime());
			assertThat("local user does not match. Created date was not checked.", user,
					is(this.user));
			// TODO TEST mock date generation
			assertThat("creation date not within 1000ms",
					TestCommon.dateWithin(user.getCreated(), 1000), is(true));
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

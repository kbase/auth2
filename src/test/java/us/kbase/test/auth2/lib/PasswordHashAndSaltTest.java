package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.test.auth2.TestCommon;

public class PasswordHashAndSaltTest {

	@Test
	public void construct() {
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(
				new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				new byte[] {11, 12});
		assertThat("incorrect hash", creds.getPasswordHash(),
				is(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
		assertThat("incorrect salt", creds.getSalt(),
				is(new byte[] {11, 12}));
	}
	
	@Test
	public void clear() {
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(
				new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				new byte[] {11, 12});
		creds.clear();
		assertThat("incorrect hash", creds.getPasswordHash(),
				is(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
		assertThat("incorrect salt", creds.getSalt(),
				is(new byte[] {0, 0}));
	}
	
	@Test
	public void constructFail() {
		failConstruct(null, new byte[2],
				new IllegalArgumentException("passwordHash missing or too small"));
		failConstruct(new byte[9], new byte[2],
				new IllegalArgumentException("passwordHash missing or too small"));
		failConstruct(new byte[10], null,
				new IllegalArgumentException("salt missing or too small"));
		failConstruct(new byte[10], new byte[1],
				new IllegalArgumentException("salt missing or too small"));
	}

	private void failConstruct(
			final byte[] hash,
			final byte[] salt,
			final Exception e) {
		try {
			new PasswordHashAndSalt(hash, salt);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

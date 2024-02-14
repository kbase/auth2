package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.cryptutils.SHA1RandomDataGenerator;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.test.auth2.TestCommon;

public class PasswordTest {
	
	@Test
	public void constructor() throws Exception {
		final char[] pwd = "this is a password".toCharArray();
		final Password p = new Password(pwd);
		assertThat("incorrect password", p.getPassword(), is(pwd));
	}
	
	@Test
	public void nullConstructor() throws Exception {
		try {
			new Password(null);
			fail("created bad password");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("password"));
		}
	}
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(Password.class).usingGetClass().verify();
	}
	
	@Test
	public void clearClassMethod() throws Exception {
		final char[] pwd = "this is also a password".toCharArray();
		final Password p = new Password(pwd);
		p.clear();
		assertThat("clear failed", p.getPassword(), is("00000000000000000000000".toCharArray()));
	}
	
	@Test
	public void clearStaticMethod() throws Exception {
		final char[] pwd = "this is also a password".toCharArray();
		Password.clearPasswordArray(pwd);
		assertThat("clearPasswordArray failed", pwd, is("00000000000000000000000".toCharArray()));
		// This should work and be a no-op
		Password.clearPasswordArray(null);
	}
	
	@Test
	public void passValidityCheck() throws Exception {
		final char[] pwd = new SHA1RandomDataGenerator().getTemporaryPassword(256);
		new Password(pwd).checkValidity();
	}
	
	@Test
	public void passValidityCheckUnicode() throws Exception {
		final char[] pwd = randomUnicode(256);
		assertThat("incorrect length", pwd.length, is(256 * 2));
		new Password(pwd).checkValidity();
	}

	private char[] randomUnicode(final int codePoints) {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < codePoints; i ++) {
			sb.appendCodePoint(70000 + (int)(Math.random() * 10000));
		}
		return sb.toString().toCharArray();
	}
	
	@Test
	public void passwordTooLong() throws Exception {
		failValidate(TestCommon.LONG1001.substring(0, 257), "Password exceeds max length");
	}
	
	@Test
	public void passwordTooLongUnicode() throws Exception {
		final char[] pwd = randomUnicode(257);
		assertThat("incorrect length", pwd.length, is(257 * 2));
		failValidate(new String(pwd), "Password exceeds max length");
	}
	
	@Test
	public void passwordStrengthCheck() throws Exception {
		failPasswordStrength("");
		failPasswordStrength("12345");
		failPasswordStrength("password");
		failPasswordStrength("open");
	}
	
	private void failPasswordStrength(final String pwd) {
		failValidate(pwd, "Password is not strong enough");
	}

	private void failValidate(final String pwd, final String exceptionPart) {
		Password password = new Password(pwd.toCharArray());
		try {
			password.checkValidity();
			fail("validated a bad password (" + pwd + ")");
		} catch (IllegalPasswordException e) {
			TestCommon.assertExceptionMessageContains(e, exceptionPart);
		}
	}
}

package us.kbase.test.auth2.cryptutils;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.UUID;

import org.apache.commons.codec.binary.Base32;
import org.junit.Test;

import us.kbase.auth2.cryptutils.SHA1RandomDataGenerator;
import us.kbase.test.auth2.TestCommon;

public class SHA1RandomDataGeneratorTest {
	
	public static final String PASSWORD_CHARACTERS =
			"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789+!@$%&*";
	
	@Test
	public void getToken() throws Exception {
		// not much to test here other than it's base32 compatible and the right # of bytes
		final SHA1RandomDataGenerator gen = new SHA1RandomDataGenerator();
		final String t = gen.getToken();
		final byte[] b = new Base32().decode(t);
		assertThat("incorrect byte count", b.length, is(20));
		
		for (final int size: Arrays.asList(1, 2, 3, 4, 5, 8, 10, 20)) {
			final String tok = gen.getToken(size);
			final byte[] dec = new Base32().decode(tok);
			assertThat("incorrect byte count", dec.length, is(5 * size));
		}
	}
	
	@Test
	public void getTokenFail() throws Exception {
		final SHA1RandomDataGenerator gen = new SHA1RandomDataGenerator();
		for (final int size: Arrays.asList(0, -1, -5, -10, -100, -1000, Integer.MIN_VALUE)) {
			try {
				gen.getToken(size);
				fail("expected exception");
			} catch (Exception got) {
				TestCommon.assertExceptionCorrect(
						got, new IllegalArgumentException("sizeMultiple must be > 0"));
			}
		}
		
	}
	
	@Test
	public void failCreatePassword() throws Exception {
		try {
			new SHA1RandomDataGenerator().getTemporaryPassword(7);
			fail("got bad temp pwd");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("length must be > 7"));
		}
	}
	
	@Test
	public void getTempPwd() throws Exception {
		//again not much to test here other than the size is right and the characters are correct
		final char[] pwd = new SHA1RandomDataGenerator().getTemporaryPassword(8);
		assertThat("incorrect pwd length", pwd.length, is(8));
		for (final char c: pwd) {
			if (PASSWORD_CHARACTERS.indexOf(c) < 0) {
				fail("Illegal character in pwd: " + c);
			}
		}
	}
	
	@Test
	public void generateSalt() throws Exception {
		// not much to test here other than it returns an 8 byte array
		// even all 0s is a valid output
		final byte[] salt = new SHA1RandomDataGenerator().generateSalt();
		assertThat("incorrect salt length", salt.length, is(8));
	}
	
	@Test
	public void uuid() throws Exception {
		// not much to test here
		assertThat("doesn't generate a uuid", new SHA1RandomDataGenerator().randomUUID(),
				instanceOf(UUID.class));
	}

}

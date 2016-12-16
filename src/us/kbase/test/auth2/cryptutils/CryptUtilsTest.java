package us.kbase.test.auth2.cryptutils;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.LinkedList;
import java.util.List;

import org.junit.Test;

import us.kbase.auth2.cryptutils.PasswordCrypt;

public class CryptUtilsTest {

	//TODO TEST add test runner to ant
	
	@Test
	public void nulls() throws Exception {
		final PasswordCrypt pc = new PasswordCrypt();
		try {
			pc.getEncryptedPassword(null, new byte[10]);
			fail("expected NPE");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password and salt cannot be null"));
		}
		try {
			pc.getEncryptedPassword(new char[10], null);
			fail("expected NPE");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password and salt cannot be null"));
		}
		try {
			pc.authenticate(null, new byte[10], new byte[10]);
			fail("expected NPE");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password and salt cannot be null"));
		}
		try {
			pc.authenticate(new char[10], null, new byte[10]);
			fail("expected NPE");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Passwords cannot be null"));
		}
		try {
			pc.authenticate(new char[10], new byte[10], null);
			fail("expected NPE");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password and salt cannot be null"));
		}
	}
	
	@Test
	public void generateSalt() throws Exception {
		// not much to test here other than it returns an 8 byte array
		// even all 0s is a valid output
		final byte[] salt = new PasswordCrypt().generateSalt();
		assertThat("incorrect salt length", salt.length, is(8));
	}
	
	@Test
	public void shortSalt() throws Exception {
		try {
			new PasswordCrypt().getEncryptedPassword("f".toCharArray(), new byte[0]);
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("salt must be at least 1 byte"));
		}
		try {
			new PasswordCrypt().authenticate("f".toCharArray(), bytesFromHex("00"), new byte[0]);
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("salt must be at least 1 byte"));
		}
	}
	
	@Test
	public void shortPwd() throws Exception {
		final byte[] b = bytesFromHex("00");
		try {
			new PasswordCrypt().getEncryptedPassword("".toCharArray(), b);
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password must be at least 1 character"));
		}
		try {
			new PasswordCrypt().authenticate("".toCharArray(), b, b);
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("password must be at least 1 character"));
		}
	}
	
	@Test
	public void encryptAndAuthenticate() throws Exception {
		final PasswordCrypt pc = new PasswordCrypt();
		final char[] pwd = "foo".toCharArray();
		final byte[] salt = bytesFromHex("4f", "56", "0a");
		final byte[] expected = bytesFromHex("50", "79", "49", "C8", "4A", "8F", "DC", "74",
				"2E", "19", "6B", "E1", "16", "23", "47", "B4", "DD", "E6", "2B", "9D", 
				"EB", "D5", "83", "19", "FA", "D8", "60", "F8", "E1", "11", "8C", "12");
		final byte[] enc = pc.getEncryptedPassword(pwd, salt);
		assertThat("incorrect encrpyted password", enc, is(expected));
		assertThat("failed to authenticate", pc.authenticate(pwd, enc, salt), is(true));
		
		// test wrong pwd
		assertThat("authentication succeeded when fail expected",
				pc.authenticate("foi".toCharArray(), enc, salt), is(false));
		
		// test shorter encrypted pwd
		final byte[] encshort = new byte[enc.length - 1];
		System.arraycopy(enc, 0, encshort, 0, enc.length - 1);
		assertThat("authentication succeeded when fail expected",
				pc.authenticate(pwd, encshort, salt), is(false));
		
		// test longer encrypted pwd
		final byte[] enclong = new byte[enc.length + 1];
		System.arraycopy(enc, 0, enclong, 0, enc.length);
		enclong[enclong.length - 1] = (byte) 0xa4;
		assertThat("authentication succeeded when fail expected",
				pc.authenticate(pwd, enclong, salt), is(false));
	}
	
	private byte[] bytesFromHex(final String... hex) {
		final byte[] b = new byte[hex.length];
		for (int i = 0; i < hex.length; i++) {
			b[i] = (byte) (Integer.parseInt(hex[i], 16) & 0xff);
		}
		return b;
	}
	
	@SuppressWarnings("unused")
	private void printBytesAsHex(final byte[] bytes) {
		final List<String> hex = new LinkedList<>(); 
		for (byte b : bytes) {
			hex.add(String.format("\"%02X\"", b));
		}
		System.out.println(String.join(", ", hex));
	}
	
}

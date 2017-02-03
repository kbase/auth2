package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.Password;
import us.kbase.test.auth2.TestCommon;

public class PasswordTest {
	
	//TODO TEST these will need to change once the strength checker is in place
	
	@Test
	public void constructor() throws Exception {
		final char[] pwd = "this is a password".toCharArray();
		final Password p = new Password(pwd);
		assertThat("incorrect password", p.getPassword(), is(pwd));
		
	}
	
	@Test
	public void nullConstructor() throws Exception {
		failCreate(null, new NullPointerException("password"));
	}
	
	@Test
	public void clear() throws Exception {
		final char[] pwd = "this is also a password".toCharArray();
		final Password p = new Password(pwd);
		p.clear();
		assertThat("clear failed", p.getPassword(), is("00000000000000000000000".toCharArray()));
	}
	
	
	private void failCreate(final char[] pwd, final Exception e) throws Exception {
		try {
			new Password(pwd);
			fail("created bad password");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}

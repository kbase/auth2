package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class UserNameTest {
	
	@Test
	public void root() throws Exception {
		final UserName un = new UserName("***ROOT***");
		assertThat("incorrect username", un.getName(), is("***ROOT***"));
		assertThat("incorrect is root", un.isRoot(), is(true));
		assertThat("incorrect toString", un.toString(), is("UserName [name=***ROOT***]"));
		assertThat("incorrect hashCode" , un.hashCode(), is(-280622915));
		
		final UserName un2 = UserName.ROOT;
		assertThat("incorrect username", un2.getName(), is("***ROOT***"));
		assertThat("incorrect is root", un2.isRoot(), is(true));
		assertThat("incorrect toString", un2.toString(), is("UserName [name=***ROOT***]"));
		assertThat("incorrect hashCode" , un2.hashCode(), is(-280622915));
	}
	
	@Test
	public void construct() throws Exception {
		final UserName un = new UserName("a8nba9");
		assertThat("incorrect username", un.getName(), is("a8nba9"));
		assertThat("incorrect is root", un.isRoot(), is(false));
		assertThat("incorrect toString", un.toString(), is("UserName [name=a8nba9]"));
		assertThat("incorrect hashCode" , un.hashCode(), is(-1462848190));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("user name"));
		failConstruct("   \t \n    ", new MissingParameterException("user name"));
		failConstruct("9aabaea", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
				"Username must start with a letter"));
		failConstruct("abaeataΔfoo", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
				"Illegal character in user name abaeataΔfoo: Δ"));
		failConstruct("abaea*tafoo", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
				"Illegal character in user name abaea*tafoo: *"));
		failConstruct(TestCommon.LONG101, new IllegalParameterException(
				ErrorType.ILLEGAL_PARAMETER,
				"user name size greater than limit 100"));
	}

	private void failConstruct(
			final String name,
			final Exception exception) {
		try {
			new UserName(name);
			fail("constructed bad name");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void equals() throws Exception {
		final UserName un1 = new UserName("foo");
		assertThat("incorrect equality", un1.equals(un1), is(true));
		assertThat("incorrect null", un1.equals(null), is(false));
		assertThat("incorrect type", un1.equals("foo"), is(false));
		assertThat("incorrect bad name", un1.equals(new UserName("bar")), is(false));
		assertThat("incorrect good name", un1.equals(new UserName("foo")), is(true));
	}
	
	@Test
	public void santitize() throws Exception {
		assertThat("incorrect santize", UserName.sanitizeName("999aFA8 ea6t  \t   ѱ ** J(())"),
				is(new UserName("afa8ea6tj")));
		assertThat("incorrect santize", UserName.sanitizeName("999  8 6  \t   ѱ ** (())"),
				is((UserName) null));
	}
	
}

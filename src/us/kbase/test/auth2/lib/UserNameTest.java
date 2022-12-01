package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
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
		assertThat("incorrect toString", un.toString(), is("UserName [getName()=***ROOT***]"));
		assertThat("incorrect hashCode" , un.hashCode(), is(-280622915));
		
		final UserName un2 = UserName.ROOT;
		assertThat("incorrect username", un2.getName(), is("***ROOT***"));
		assertThat("incorrect is root", un2.isRoot(), is(true));
		assertThat("incorrect toString", un2.toString(), is("UserName [getName()=***ROOT***]"));
		assertThat("incorrect hashCode" , un2.hashCode(), is(-280622915));
	}
	
	@Test
	public void construct() throws Exception {
		final UserName un = new UserName("a8nba9");
		assertThat("incorrect username", un.getName(), is("a8nba9"));
		assertThat("incorrect is root", un.isRoot(), is(false));
		assertThat("incorrect toString", un.toString(), is("UserName [getName()=a8nba9]"));
		assertThat("incorrect hashCode" , un.hashCode(), is(-1462848190));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("user name"));
		failConstruct("   \t \n    ", new MissingParameterException("user name"));
		failConstruct("9aabaea", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
				"Username must start with a letter"));
		failConstruct("abaeataDfoo", new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
				"Illegal character in user name abaeataDfoo: D"));
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
	public void compareLessThan() throws Exception {
		assertThat("incorrect compare",
				new UserName("foo123").compareTo(new UserName("foo2")) < 0, is(true));
	}
	
	@Test
	public void compareEquals() throws Exception {
		assertThat("incorrect compare",
				new UserName("foo2").compareTo(new UserName("foo2")), is(0));
	}
	
	@Test
	public void compareGreaterThan() throws Exception {
		assertThat("incorrect compare",
				new UserName("foo13").compareTo(new UserName("foo111")) > 0, is(true));
	}
	
	@Test
	public void compareFail() throws Exception {
		try {
			new UserName("foo").compareTo(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("name"));
		}
	}
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(UserName.class).usingGetClass().verify();
	}
	
	@Test
	public void sanitize() throws Exception {
		assertThat("incorrect santize", UserName.sanitizeName("  999aFA8 ea6t  \t   ѱ ** J(())"),
				is(Optional.of(new UserName("afa8ea6tj"))));
		assertThat("incorrect santize", UserName.sanitizeName("999  8 6  \t   ѱ ** (())"),
				is(Optional.empty()));
	}
	
	@Test
	public void failSanitize() {
		try {
			UserName.sanitizeName(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("suggestedUserName"));
		}
	}
	
}

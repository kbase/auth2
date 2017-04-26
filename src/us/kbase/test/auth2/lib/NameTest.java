package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.Name;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class NameTest {
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(Name.class).usingGetClass().verify();
	}
	
	@Test
	public void construct() throws Exception {
		final Name n = new Name("     foo     ", "bar", 3);
		assertThat("incorrect name", n.getName(), is("foo"));
		
		final Name n2 = new Name("     fo𐎣o     ", "bar", 4);
		assertThat("incorrect name", n2.getName(), is("fo𐎣o"));
		
		final Name n3 = new Name("     foo     ", "bar", 0);
		assertThat("incorrect name", n3.getName(), is("foo"));
	}
	
	@Test
	public void check() throws Exception {
		assertThat("incorrect name", Name.checkValidName("     foo     ", "bar", 3), is("foo"));
		assertThat("incorrect name", Name.checkValidName("     𐎣foo     ", "bar", 4), is("𐎣foo"));
		assertThat("incorrect name", Name.checkValidName("     𐎣foo     ", "bar", 0), is("𐎣foo"));
	}
	
	private static class SubName extends Name {
		
		public SubName(final String n)
				throws MissingParameterException, IllegalParameterException {
			super(n, "n", 20);
		}
	}
	
	@Test
	public void tostring() throws Exception {
		assertThat("incorrect toString()", new Name("foo", "a",  4).toString(),
				is("Name [name=foo]"));
		assertThat("incorrect toString()", new SubName("bar").toString(),
				is("SubName [name=bar]"));
	}
	
	@Test
	public void constructFail() {
		failConstruct("foo", null, 3, new IllegalArgumentException("Missing argument: type"));
		failConstruct("foo", "   \t \n    ", 3,
				new IllegalArgumentException("Missing argument: type"));
		failConstruct(null, "thing", 1, new MissingParameterException("thing"));
		failConstruct("    \t    \n    ", "thing", 1, new MissingParameterException("thing"));
		failConstruct("     fo𐎣o     ", "thing", 3,
				new IllegalParameterException("thing size greater than limit 3"));
		failConstruct("     fo\b𐎣o     ", "thing", 5,
				new IllegalParameterException("thing contains control characters"));
	}
	
	@Test
	public void checkFail() {
		failCheck("foo", null, 3, new IllegalArgumentException("Missing argument: type"));
		failCheck("foo", "   \t \n    ", 3,
				new IllegalArgumentException("Missing argument: type"));
		failCheck(null, "thing", 1, new MissingParameterException("thing"));
		failCheck("    \t    \n    ", "thing", 1, new MissingParameterException("thing"));
		failCheck("     fo𐎣o     ", "thing", 3,
				new IllegalParameterException("thing size greater than limit 3"));
		failCheck("     fo\b𐎣o     ", "thing", 5,
				new IllegalParameterException("thing contains control characters"));
	}
	
	@Test
	public void compareTo() throws Exception {
		assertThat("incorrect compare for < ",
				new Name("bar", "n", 5).compareTo(new Name("foo", "n", 5)) < 0, is(true));
		
		assertThat("incorrect compare for < ",
				new Name("bar", "n", 5).compareTo(new Name("bar", "n", 5)), is(0));
		assertThat("incorrect compare for < ",
				new Name("foo", "n", 5).compareTo(new Name("bar", "n", 5)) > 0, is(true));
		
		try {
			new Name("bar", "n", 5).compareTo(null);
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new NullPointerException("name"));
		}
	}
	
	private void failConstruct(
			final String name,
			final String type,
			final int maxCodePoints,
			final Exception e) {
		try {
			new Name(name, type, maxCodePoints);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCheck(
			final String name,
			final String type,
			final int maxCodePoints,
			final Exception e) {
		try {
			Name.checkValidName(name, type, maxCodePoints);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}

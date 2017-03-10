package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import org.junit.Test;

import us.kbase.auth2.lib.Utils;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class UtilsTest {

	@Test
	public void addLong(){
		assertThat("incorrect add", Utils.addNoOverflow(8, 9), is (17L));
		assertThat("incorrect add", Utils.addNoOverflow(-8, 9), is (1L));
		assertThat("incorrect add", Utils.addNoOverflow(0, 0), is (0L));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MAX_VALUE - 10, 9),
				is(Long.MAX_VALUE - 1));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MAX_VALUE - 10, 10),
				is(Long.MAX_VALUE));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MAX_VALUE - 10, 11),
				is(Long.MAX_VALUE));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MIN_VALUE + 10, -9),
				is(Long.MIN_VALUE + 1));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MIN_VALUE + 10, -10),
				is(Long.MIN_VALUE));
		assertThat("incorrect add", Utils.addNoOverflow(Long.MIN_VALUE + 10, -11),
				is(Long.MIN_VALUE));
	}
	
	@Test
	public void clear() {
		final byte[] b = "foobar".getBytes();
		Utils.clear(b);
		assertThat("clear failed", b, is(new byte[6]));
		
		Utils.clear(null); // noop
	}
	
	@Test
	public void checkString() throws Exception {
		Utils.checkString(TestCommon.LONG1001, "name");
		Utils.checkStringNoCheckedException(TestCommon.LONG1001, "name");
		Utils.checkString("ok", "name", 2);
		Utils.checkString(" \n  ok   \t", "name", 2);
	}
	
	@Test
	public void checkStringFail() throws Exception {
		failCheckString(null, "foo", new MissingParameterException("foo"));
		failCheckString("    \n \t  ", "foo", new MissingParameterException("foo"));
	}

	@Test
	public void checkStringUncheckedFail() throws Exception {
		failCheckStringUnchecked(null, "foo",
				new IllegalArgumentException("Missing argument: foo"));
		failCheckStringUnchecked("    \n \t  ", "foo",
				new IllegalArgumentException("Missing argument: foo"));
	}
	
	@Test
	public void checkStringLengthFail() throws Exception {
		failCheckString(null, "foo", 1, new MissingParameterException("foo"));
		failCheckString("    \n \t  ", "foo", 1, new MissingParameterException("foo"));
		failCheckString("abc", "foo", 2,
				new IllegalParameterException("foo size greater than limit 2"));
	}
	
	@Test
	public void unicodeAndLength() throws Exception {
		final String s = "ab𐎂c";
		assertThat("incorrect String length", s.length(), is(5));
		Utils.checkString(s, "foo", 4);
		failCheckString(s, "foo", 3,
				new IllegalParameterException("foo size greater than limit 3"));
	}
	
	private void failCheckString(final String s, final String name, final Exception e) {
		try {
			Utils.checkString(s, name);
			fail("check string failed");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCheckStringUnchecked(final String s, final String name, final Exception e) {
		try {
			Utils.checkStringNoCheckedException(s, name);
			fail("check string failed");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failCheckString(
			final String s,
			final String name,
			final int length,
			final Exception e) {
		try {
			Utils.checkString(s, name, length);
			fail("check string failed");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void noNullsCollection() throws Exception {
		Utils.noNulls(Arrays.asList("foo", "bar"), "whee"); // should work
	}
	
	@Test
	public void noNullsCollectionFail() throws Exception {
		failNoNullsCollection(new HashSet<>(Arrays.asList("foo", null, "bar")), "whee");
		failNoNullsCollection(Arrays.asList("foo", null, "bar"), "whee1");
	}
	
	private void failNoNullsCollection(final Collection<?> col, final String message) {
		try {
			Utils.noNulls(col, message);
			fail("expected exception");
		} catch (NullPointerException npe) {
			assertThat("incorrect exception message", npe.getMessage(), is(message));
		}
	}
	
	@Test
	public void nonNull() {
		Utils.nonNull(new Object(), "foo"); // should work
	}
	
	@Test
	public void failNonNull() {
		try {
			Utils.nonNull(null, "foo");
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("foo"));
		}
	}
	
}

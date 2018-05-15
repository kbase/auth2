package us.kbase.test.auth2.service.common;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.service.common.IncomingJSON;
import us.kbase.test.auth2.TestCommon;

public class IncomingJSONTest {
	
	@Test
	public void getString() throws Exception {
		final String res = IncomingJSON.getString("  \t    fooo  \n  ", "foo");
		assertThat("incorrect string", res, is("fooo"));
	}
	
	@Test
	public void getStringFailNullOrEmpty() throws Exception {
		failGetString(null, "foobar", "foobar");
		failGetString("  \t   \n   ", "foobar", "foobar");
	}
	
	
	private void failGetString(final String s, final String field, final String exception) {
		try {
			IncomingJSON.getString(s, field);
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new MissingParameterException(field));
		}
	}
	
	private class IncomingJSONSub extends IncomingJSON {
		
		public IncomingJSONSub() {}
		
		@Override
		public Optional<String> getOptionalString(final String s) {
			return super.getOptionalString(s);
		}
		
		@Override
		public boolean getBoolean(final Object bool, final String fieldName)
				throws IllegalParameterException {
			return super.getBoolean(bool, fieldName);
		}
	}
	
	@Test
	public void getOptionalStringPresent() throws Exception {
		final Optional<String> res = new IncomingJSONSub().getOptionalString("   \t    foo\n ");
		assertThat("incorrect string", res, is(Optional.of("foo")));
	}
	
	@Test
	public void getOptionalStringAbsent() throws Exception {
		final Optional<String> res = new IncomingJSONSub().getOptionalString(null);
		assertThat("incorrect string", res, is(Optional.absent()));
		
		final Optional<String> res2 = new IncomingJSONSub().getOptionalString("   \t    \n   ");
		assertThat("incorrect string", res2, is(Optional.absent()));
	}
	
	@Test
	public void getBooleanTrue() throws Exception {
		final boolean b = new IncomingJSONSub().getBoolean(Boolean.TRUE, "foo");
		assertThat("incorrect boolean", b, is(true));
		
		final boolean b2 = new IncomingJSONSub().getBoolean(true, "foo");
		assertThat("incorrect boolean", b2, is(true));
	}
	
	@Test
	public void getBooleanFalse() throws Exception {
		final boolean b = new IncomingJSONSub().getBoolean(Boolean.FALSE, "foo");
		assertThat("incorrect boolean", b, is(false));
		
		final boolean b2 = new IncomingJSONSub().getBoolean(false, "foo");
		assertThat("incorrect boolean", b2, is(false));
		
		final boolean b3 = new IncomingJSONSub().getBoolean(null, "foo");
		assertThat("incorrect boolean", b3, is(false));
	}
	
	@Test
	public void getBooleanFail() {
		try {
			new IncomingJSONSub().getBoolean("s", "foo");
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e,
					new IllegalParameterException("foo must be a boolean"));
		}
	}
	
	@Test
	public void setAndGetAdditionalProps() {
		final IncomingJSON ij = new IncomingJSONSub();
		ij.setAdditionalProperties("foo", "bar");
		ij.setAdditionalProperties("baz", "bat");
		assertThat("incorrect addt'l props", ij.getAdditionalProperties(),
				is(ImmutableMap.of("foo", "bar", "baz", "bat")));
	}
	
	@Test
	public void exceptOnAdditionalProps() throws Exception {
		final IncomingJSON ij = new IncomingJSONSub();
		ij.exceptOnAdditionalProperties(); // shouldn't except
		ij.setAdditionalProperties("foo", "bar");
		try {
			ij.exceptOnAdditionalProperties();
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e,
					new IllegalParameterException("Unexpected parameters in request: foo"));
		}
	}

}

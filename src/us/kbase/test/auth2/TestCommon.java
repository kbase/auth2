package us.kbase.test.auth2;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.apache.commons.lang3.exception.ExceptionUtils;

public class TestCommon {

	public static void assertExceptionCorrect(
			final Exception got,
			final Exception expected) {
		assertThat("incorrect exception. trace:\n" + ExceptionUtils.getStackTrace(got),
				got.getMessage(), is(expected.getMessage()));
		assertThat("incorrect exception type", got, is(expected.getClass()));
	}
	
}

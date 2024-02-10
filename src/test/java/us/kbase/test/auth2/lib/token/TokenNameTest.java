package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.test.auth2.TestCommon;

public class TokenNameTest {
	
	@Test
	public void construct() throws Exception {
		final TokenName tn = new TokenName("foo");
		assertThat("incorrect name", tn.getName(), is("foo"));
		assertThat("incorrect toString()", tn.toString(), is("TokenName [getName()=foo]"));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("token name"));
		failConstruct("   \t   ", new MissingParameterException("token name"));
		failConstruct(TestCommon.LONG101,
				new IllegalParameterException("token name size greater than limit 100"));
	}
	
	private void failConstruct(
			final String name,
			final Exception e) {
		try {
			new TokenName(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
		
	}

}

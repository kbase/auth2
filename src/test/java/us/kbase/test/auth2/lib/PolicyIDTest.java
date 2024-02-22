package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class PolicyIDTest {

	@Test
	public void construct() throws Exception {
		final PolicyID pid = new PolicyID(TestCommon.LONG101.substring(0, 20));
		assertThat("incorrect pid", pid.getName(), is(TestCommon.LONG101.substring(0, 20)));
	}
	
	@Test
	public void constructFail() {
		failConstruct(null, new MissingParameterException("policy id"));
		failConstruct("           ", new MissingParameterException("policy id"));
		failConstruct(TestCommon.LONG101.substring(0, 31), new IllegalParameterException(
				"policy id size greater than limit 20"));
	}
	
	public void failConstruct(final String pid, final Exception e) {
		try {
			new PolicyID(pid);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}

package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class CustomRoleTest {

	@Test
	public void constructor() throws Exception {
		final CustomRole cr = new CustomRole("7_fooAZ9A", "\t    bar");
		assertThat("incorrect id", cr.getID(), is("7_fooAZ9A"));
		assertThat("incorrect description", cr.getDesc(), is("bar"));
		assertThat("incorrect toString", cr.toString(), is("CustomRole [id=7_fooAZ9A, desc=bar]"));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, "foo", new MissingParameterException("custom role id"));
		failConstruct("   \n  ", "foo", new MissingParameterException("custom role id"));
		failConstruct("bar", null, new MissingParameterException("custom role description"));
		failConstruct("bar", "   \t \n  ", new MissingParameterException("custom role description"));
		
		failConstruct(TestCommon.LONG101, "foo", new IllegalParameterException(
				ErrorType.ILLEGAL_PARAMETER,
				"custom role id size greater than limit 100"));
		failConstruct("bar", TestCommon.LONG1001, new IllegalParameterException(
				ErrorType.ILLEGAL_PARAMETER,
				"custom role description size greater than limit 1000"));
		
		failConstruct("barઔ", "foo", new IllegalParameterException(
				"Illegal character in custom role id barઔ: ઔ"));
		failConstruct("bar*", "foo", new IllegalParameterException(
				"Illegal character in custom role id bar*: *"));
		
	}

	private void failConstruct(final String id, final String desc, final Exception exception) {
		try {
			new CustomRole(id, desc);
			fail("created bad custom role");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(CustomRole.class).usingGetClass().verify();
	}
	
}

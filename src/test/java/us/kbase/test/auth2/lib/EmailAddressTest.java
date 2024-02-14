package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class EmailAddressTest {

	@Test
	public void construct() throws Exception {
		final EmailAddress ea = new EmailAddress("   foo@bar.com   \n");
		assertThat("incorrect email", ea.getAddress(), is("foo@bar.com"));
		assertThat("incorrect hashCode", ea.hashCode(), is(1827947467));
		assertThat("incorrect toString", ea.toString(), is("EmailAddress [email=foo@bar.com]"));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("email address"));
		failConstruct("   \n  ", new MissingParameterException("email address"));
		failConstruct("foo", new IllegalParameterException(ErrorType.ILLEGAL_EMAIL_ADDRESS,
				"foo"));
		failConstruct("foo@bar", new IllegalParameterException(ErrorType.ILLEGAL_EMAIL_ADDRESS,
				"foo@bar"));
		failConstruct(TestCommon.LONG1001, new IllegalParameterException(
				ErrorType.ILLEGAL_PARAMETER,
				"email address size greater than limit 1000"));
	}

	private void failConstruct(final String email, final Exception exception) {
		try {
			new EmailAddress(email);
			fail("created bad email");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(EmailAddress.class).usingGetClass().verify();
	}
	
	@Test
	public void unknown() throws Exception {
		assertThat("incorrect unknown", EmailAddress.UNKNOWN.getAddress(), is((String) null));
	}
	
}

package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.token.MFAStatus;

public class MFAStatusTest {

	@Test
	public void testValues() {
		final MFAStatus[] expected = {MFAStatus.USED, MFAStatus.NOT_USED, MFAStatus.UNKNOWN};
		assertThat("incorrect values", MFAStatus.values(), is(expected));
	}
	
	@Test
	public void testMFAStatusGetDescription() throws Exception {
		assertThat("incorrect Used description", MFAStatus.USED.getDescription(),
				is("Used"));
		assertThat("incorrect NotUsed description", MFAStatus.NOT_USED.getDescription(),
				is("NotUsed"));
		assertThat("incorrect Unknown description", MFAStatus.UNKNOWN.getDescription(),
				is("Unknown"));
	}

	@Test
	public void testMFAStatusIDsAreStableForSerialization() throws Exception {
		// These IDs are persisted to database via JSON serialization and must never change.
		// Changing these values would break backwards compatibility with existing tokens
		// and user data stored in MongoDB.
		assertThat("USED ID must be stable", MFAStatus.USED.getID(), is("Used"));
		assertThat("NOT_USED ID must be stable", MFAStatus.NOT_USED.getID(), is("NotUsed"));
		assertThat("UNKNOWN ID must be stable", MFAStatus.UNKNOWN.getID(), is("Unknown"));
	}

	@Test
	public void testMFAStatusFromIDValidValues() throws Exception {
		assertThat("incorrect fromID for Used", MFAStatus.fromID("Used"), is(MFAStatus.USED));
		assertThat("incorrect fromID for NotUsed", MFAStatus.fromID("NotUsed"),
				is(MFAStatus.NOT_USED));
		assertThat("incorrect fromID for Unknown", MFAStatus.fromID("Unknown"),
				is(MFAStatus.UNKNOWN));
	}

	@Test
	public void testFromIDFail() throws Exception {
		failFromId(null, "Invalid MFA status: null");
		failFromId("   \t   ", "Invalid MFA status:    \t   ");
		failFromId("INVALID", "Invalid MFA status: INVALID");
		failFromId("used", "Invalid MFA status: used");
	}

	private void failFromId(final String id, final String exception) {
		try {
			MFAStatus.fromID(id);
			fail("expected exception");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(), is(exception));
		}
	}
}

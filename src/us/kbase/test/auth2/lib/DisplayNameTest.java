package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class DisplayNameTest {
	
	@Test
	public void constructor() throws Exception {
		final DisplayName dn = new DisplayName("    foooΔ   ");
		assertThat("incorrect displayname", dn.getName(), is("foooΔ"));
		assertThat("incorrect toString", dn.toString(), is("DisplayName [getName()=foooΔ]"));
	}
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(DisplayName.class).usingGetClass().verify();
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("display name"));
		failConstruct("   \n  ", new MissingParameterException("display name"));
		failConstruct("    fo\no\boΔ\n", new IllegalParameterException(
				"display name contains control characters"));
		failConstruct(TestCommon.LONG101, new IllegalParameterException(
				ErrorType.ILLEGAL_PARAMETER,
				"display name size greater than limit 100"));
	}

	private void failConstruct(final String name, final Exception exception) {
		try {
			new DisplayName(name);
			fail("created bad display name");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void getCanonicalDisplayName() throws Exception {
		final String input = "whEe1   ΅·   +΅BA՞+R·   (bleΔah)  ՞  wuΞgga    bA()*&R";
		final List<String> expected = Arrays.asList("whee1", "bar", "bleδah", "wuξgga");
		final DisplayName dn = new DisplayName(input);
		assertThat("incorrect canonical name", dn.getCanonicalDisplayName(), is(expected));
		assertThat("incorrect canonical name", DisplayName.getCanonicalDisplayName(input),
			is(expected));
	}
	
	@Test
	public void getCanonicalDisplayNameFail() throws Exception {
		failGetCanonicalDisplayName(null);
		failGetCanonicalDisplayName("   \t    ");
	}
	
	private void failGetCanonicalDisplayName(final String name) {
		try {
			DisplayName.getCanonicalDisplayName(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(
					got, new IllegalArgumentException("Missing argument: name"));
		}
	}

}

package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class DisplayNameTest {
	
	private static final String LONG101;
	static {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 101; i++) {
			sb.append("a");
		}
		LONG101 = sb.toString();
	}
	
	@Test
	public void constructor() throws Exception {
		final DisplayName dn = new DisplayName("    foo\n");
		assertThat("incorrect displayname", dn.getName(), is("foo"));
		assertThat("incorrect hashCode", dn.hashCode(), is(101605));
		assertThat("incorrect toString", dn.toString(), is("DisplayName [name=foo]"));
	}
	
	@Test
	public void equals() throws Exception {
		final DisplayName dn = new DisplayName("Mrs. Entity");
		assertThat("incorrect equality", dn.equals(dn), is(true));
		assertThat("incorrect null", dn.equals(null), is(false));
		assertThat("incorrect type", dn.equals("Mrs. Entity"), is(false));
		assertThat("incorrect bad name", dn.equals(new DisplayName("Mr. Entity")), is(false));
		assertThat("incorrect good name", dn.equals(new DisplayName("Mrs. Entity")), is(true));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new MissingParameterException("display name"));
		failConstruct("   \n  ", new MissingParameterException("display name"));
		failConstruct(LONG101, new IllegalParameterException(ErrorType.ILLEGAL_PARAMETER,
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

}

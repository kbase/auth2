package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Date;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.test.auth2.TestCommon;

public class UserDisabledStateTest {

	@Test
	public void emptyConstructor() throws Exception {
		final UserDisabledState uds = new UserDisabledState();
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is((String) null));
		assertThat("incorrect by admin", uds.getByAdmin(), is((UserName) null));
		assertThat("incorrect time", uds.getTime(), is((Date) null));
	}
	
	@Test
	public void disabledConstructor() throws Exception {
		final UserDisabledState uds = new UserDisabledState("user ded",
				new UserName("foo"), new Date(67));
		assertThat("incorrect disabled state", uds.isDisabled(), is(true));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is("user ded"));
		assertThat("incorrect by admin", uds.getByAdmin(), is(new UserName("foo")));
		assertThat("incorrect time", uds.getTime(), is(new Date(67)));
	}
	
	@Test
	public void enabledConstructor() throws Exception {
		final UserDisabledState uds = new UserDisabledState(new UserName("bar"), new Date(42));
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is((String) null));
		assertThat("incorrect by admin", uds.getByAdmin(), is(new UserName("bar")));
		assertThat("incorrect time", uds.getTime(), is(new Date(42)));
	}
	
	@Test
	public void enabledConstructorFail() throws Exception {
		failEnabledConstructor(null, new Date(), new NullPointerException("byAdmin"));
		failEnabledConstructor(new UserName("foo"), null, new NullPointerException("time"));
	}
	
	@Test
	public void disabledConstructorFail() throws Exception {
		final UserName un = new UserName("foo");
		final Date d = new Date();
		failDisabledConstructor(null, un, d, new MissingParameterException("Disabled reason"));
		failDisabledConstructor("   \t \n  ", un, d,
				new MissingParameterException("Disabled reason"));
		failDisabledConstructor(TestCommon.LONG1001, un, d,
				new IllegalParameterException("Disabled reason size greater than limit 1000"));
		failDisabledConstructor("foo", null, d, new NullPointerException("byAdmin"));
		failDisabledConstructor("foo", un, null, new NullPointerException("time"));
	}
	
	private void failEnabledConstructor(
			final UserName byAdmin,
			final Date time,
			final Exception e) {
		try {
			new UserDisabledState(byAdmin, time);
			fail("created bad user disabled state");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

	private void failDisabledConstructor(
			final String reason,
			final UserName byAdmin,
			final Date time,
			final Exception e) {
		try {
			new UserDisabledState(reason, byAdmin, time);
			fail("created bad user disabled state");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void emptyCreate() throws Exception {
		final UserDisabledState uds = UserDisabledState.create(null, null, null);
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is((String) null));
		assertThat("incorrect by admin", uds.getByAdmin(), is((UserName) null));
		assertThat("incorrect time", uds.getTime(), is((Date) null));
	}
	
	@Test
	public void disabledCreate() throws Exception {
		final UserDisabledState uds = UserDisabledState.create("user ded",
				new UserName("foo"), new Date(67));
		assertThat("incorrect disabled state", uds.isDisabled(), is(true));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is("user ded"));
		assertThat("incorrect by admin", uds.getByAdmin(), is(new UserName("foo")));
		assertThat("incorrect time", uds.getTime(), is(new Date(67)));
	}
	
	@Test
	public void enabledCreate() throws Exception {
		final UserDisabledState uds = UserDisabledState.create(
				null, new UserName("bar"), new Date(42));
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is((String) null));
		assertThat("incorrect by admin", uds.getByAdmin(), is(new UserName("bar")));
		assertThat("incorrect time", uds.getTime(), is(new Date(42)));
	}
	
	@Test
	public void createFail() throws Exception {
		final UserName un = new UserName("foo");
		final Date d = new Date();
		failCreate(null, null, d,
				new IllegalStateException("If byAdmin is null time must also be null"));
		failCreate(null, un, null,
				new IllegalStateException("If byAdmin is not null time cannot be null"));
		failCreate("   \t \n  ", un, d,
				new MissingParameterException("Disabled reason"));
		failCreate(TestCommon.LONG1001, un, d,
				new IllegalParameterException("Disabled reason size greater than limit 1000"));
		failCreate("foo", null, d, new IllegalStateException(
				"If disabledReason is not null byAdmin and time cannot be null"));
		failCreate("foo", un, null, new IllegalStateException(
				"If disabledReason is not null byAdmin and time cannot be null"));
	}
	
	private void failCreate(
			final String reason,
			final UserName byAdmin,
			final Date time,
			final Exception e) {
		try {
			UserDisabledState.create(reason, byAdmin, time);
			fail("created bad user disabled state");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(UserDisabledState.class).usingGetClass().verify();
	}
}

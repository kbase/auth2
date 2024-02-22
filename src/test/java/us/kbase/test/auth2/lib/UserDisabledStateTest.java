package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Optional;
import java.time.Instant;

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
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is(Optional.empty()));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.empty()));
		assertThat("incorrect time", uds.getTime(), is(Optional.empty()));
	}
	
	@Test
	public void disabledConstructor() throws Exception {
		final UserDisabledState uds = new UserDisabledState("user ded",
				new UserName("foo"), Instant.ofEpochMilli(67));
		assertThat("incorrect disabled state", uds.isDisabled(), is(true));
		assertThat("incorrect disabled reason", uds.getDisabledReason(),
				is(Optional.of("user ded")));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.of(new UserName("foo"))));
		assertThat("incorrect time", uds.getTime(), is(Optional.of(Instant.ofEpochMilli(67))));
	}
	
	@Test
	public void enabledConstructor() throws Exception {
		final UserDisabledState uds = new UserDisabledState(new UserName("bar"),
				Instant.ofEpochMilli(42));
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is(Optional.empty()));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect time", uds.getTime(), is(Optional.of(Instant.ofEpochMilli(42))));
	}
	
	@Test
	public void enabledConstructorFail() throws Exception {
		failEnabledConstructor(null, Instant.now(), new NullPointerException("byAdmin"));
		failEnabledConstructor(new UserName("foo"), null, new NullPointerException("time"));
	}
	
	@Test
	public void disabledConstructorFail() throws Exception {
		final UserName un = new UserName("foo");
		final Instant d = Instant.now();
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
			final Instant time,
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
			final Instant time,
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
		final UserDisabledState uds = UserDisabledState.create(
				Optional.empty(), Optional.empty(), Optional.empty());
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is(Optional.empty()));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.empty()));
		assertThat("incorrect time", uds.getTime(), is(Optional.empty()));
	}
	
	@Test
	public void disabledCreate() throws Exception {
		final UserDisabledState uds = UserDisabledState.create(Optional.of("user ded"),
				Optional.of(new UserName("foo")), Optional.of(Instant.ofEpochMilli(67)));
		assertThat("incorrect disabled state", uds.isDisabled(), is(true));
		assertThat("incorrect disabled reason", uds.getDisabledReason(),
				is(Optional.of("user ded")));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.of(new UserName("foo"))));
		assertThat("incorrect time", uds.getTime(), is(Optional.of(Instant.ofEpochMilli(67))));
	}
	
	@Test
	public void enabledCreate() throws Exception {
		final UserDisabledState uds = UserDisabledState.create(
				Optional.empty(), Optional.of(new UserName("bar")),
				Optional.of(Instant.ofEpochMilli(42)));
		assertThat("incorrect disabled state", uds.isDisabled(), is(false));
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is(Optional.empty()));
		assertThat("incorrect by admin", uds.getByAdmin(), is(Optional.of(new UserName("bar"))));
		assertThat("incorrect time", uds.getTime(), is(Optional.of(Instant.ofEpochMilli(42))));
	}
	
	@Test
	public void createFail() throws Exception {
		final Optional<UserName> un = Optional.of(new UserName("foo"));
		final Optional<Instant> d = Optional.of(Instant.now());
		failCreate(null, Optional.empty(), Optional.empty(),
				new NullPointerException("disabledReason"));
		failCreate(Optional.empty(), null, Optional.empty(),
				new NullPointerException("byAdmin"));
		failCreate(Optional.empty(), Optional.empty(), null,
				new NullPointerException("time"));
		failCreate(Optional.empty(), Optional.empty(), d,
				new IllegalStateException("If byAdmin is absent time must also be absent"));
		failCreate(Optional.empty(), un, Optional.empty(),
				new IllegalStateException("If byAdmin is present time cannot be absent"));
		failCreate(Optional.of("   \t \n  "), un, d,
				new MissingParameterException("Disabled reason"));
		failCreate(Optional.of(TestCommon.LONG1001), un, d,
				new IllegalParameterException("Disabled reason size greater than limit 1000"));
		failCreate(Optional.of("foo"), Optional.empty(), d, new IllegalStateException(
				"If disabledReason is present byAdmin and time cannot be absent"));
		failCreate(Optional.of("foo"), un, Optional.empty(), new IllegalStateException(
				"If disabledReason is present byAdmin and time cannot be absent"));
	}
	
	private void failCreate(
			final Optional<String> reason,
			final Optional<UserName> byAdmin,
			final Optional<Instant> time,
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
	
	@Test
	public void toStringEmpty() {
		final UserDisabledState uds = new UserDisabledState();
		assertThat("incorrect toString", uds.toString(),
				is("UserDisabledState [disabledReason=Optional.empty, " +
				"byAdmin=Optional.empty, time=Optional.empty]"));
	}
	
	@Test
	public void toStringFull() throws Exception {
		final Instant t = Instant.ofEpochMilli(7000);
		final UserDisabledState uds = new UserDisabledState("foo", new UserName("bar"), t);
		assertThat("incorrect toString", uds.toString(), is(
				"UserDisabledState [disabledReason=Optional[foo], " +
				"byAdmin=Optional[UserName [getName()=bar]], " +
				"time=Optional[1970-01-01T00:00:07Z]]"));
	}
}

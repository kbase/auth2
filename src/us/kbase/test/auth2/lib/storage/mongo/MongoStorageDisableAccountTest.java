package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageDisableAccountTest extends MongoStorageTester {
	
	private static final Instant NOW = Instant.now();

	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void disableAccountTwice() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		assertThat("account already disabled",
				storage.getUser(new UserName("foo")).getDisabledState(),
				is(new UserDisabledState()));
		
		storage.disableAccount(new UserName("foo"), new UserName("baz"), "foo is a jerkface");
		
		final UserDisabledState uds = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds.getDisabledReason(),
				is(Optional.of("foo is a jerkface")));
		assertThat("incorrect disabled admin", uds.getByAdmin(),
				is(Optional.of(new UserName("baz"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds.getTime().get()), 200);
		
		Thread.sleep(250);
		
		storage.disableAccount(new UserName("foo"), new UserName("bung"), "foo is a doodyface");
		
		final UserDisabledState uds2 = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds2.getDisabledReason(),
				is(Optional.of("foo is a doodyface")));
		assertThat("incorrect disabled admin", uds2.getByAdmin(),
				is(Optional.of(new UserName("bung"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds2.getTime().get()), 200);
	}
	
	@Test
	public void disableFailNullsAndEmpties() throws Exception {
		failDisableAccount(null, new UserName("admin"), "foo",
				new NullPointerException("userName"));
		failDisableAccount(new UserName("foo"), null, "foo",
				new NullPointerException("admin"));
		failDisableAccount(new UserName("foo"), new UserName("admin"), null,
				new IllegalArgumentException("reason cannot be null or empty"));
		failDisableAccount(new UserName("foo"), new UserName("admin"), "   \t \n   ",
				new IllegalArgumentException("reason cannot be null or empty"));
	}
	
	@Test
	public void disableFailNoUser() throws Exception {
		failDisableAccount(new UserName("foo"), new UserName("admin"), "foo",
				new NoSuchUserException("foo"));
	}
	
	private void failDisableAccount(
			final UserName name,
			final UserName admin,
			final String reason,
			final Exception e) {
		try {
			storage.disableAccount(name, admin, reason);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void enableAccountTwice() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		assertThat("account already disabled",
				storage.getUser(new UserName("foo")).getDisabledState(),
				is(new UserDisabledState()));
		
		storage.enableAccount(new UserName("foo"), new UserName("baz"));
		
		final UserDisabledState uds = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds.getDisabledReason(), is(Optional.absent()));
		assertThat("incorrect disabled admin", uds.getByAdmin(),
				is(Optional.of(new UserName("baz"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds.getTime().get()), 200);
		
		Thread.sleep(250);
		
		storage.enableAccount(new UserName("foo"), new UserName("bung"));
		
		final UserDisabledState uds2 = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds2.getDisabledReason(), is(Optional.absent()));
		assertThat("incorrect disabled admin", uds2.getByAdmin(),
				is(Optional.of(new UserName("bung"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds2.getTime().get()), 200);
	}
	
	@Test
	public void enableFailNulls() throws Exception {
		failEnableAccount(null, new UserName("admin"), new NullPointerException("userName"));
		failEnableAccount(new UserName("foo"), null, new NullPointerException("admin"));
	}
	
	@Test
	public void enableFailNoUser() throws Exception {
		failEnableAccount(new UserName("foo"), new UserName("admin"),
				new NoSuchUserException("foo"));
	}
	
	private void failEnableAccount(
			final UserName name,
			final UserName admin,
			final Exception e) {
		try {
			storage.enableAccount(name, admin);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

	@Test
	public void disableEnableDisable() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		assertThat("account already disabled",
				storage.getUser(new UserName("foo")).getDisabledState(),
				is(new UserDisabledState()));
		
		storage.disableAccount(new UserName("foo"), new UserName("baz"), "foo is a jerkface");
		
		final UserDisabledState uds = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds.getDisabledReason(),
				is(Optional.of("foo is a jerkface")));
		assertThat("incorrect disabled admin", uds.getByAdmin(),
				is(Optional.of(new UserName("baz"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds.getTime().get()), 200);
		
		Thread.sleep(250);
		
		storage.enableAccount(new UserName("foo"), new UserName("bat"));
		
		final UserDisabledState uds2 = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds2.getDisabledReason(), is(Optional.absent()));
		assertThat("incorrect disabled admin", uds2.getByAdmin(),
				is(Optional.of(new UserName("bat"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds2.getTime().get()), 200);
		
		Thread.sleep(250);
		
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "foo is a dorkyface");
		
		final UserDisabledState uds3 = storage.getUser(new UserName("foo")).getDisabledState();
		assertThat("incorrect disabled reason", uds3.getDisabledReason(),
				is(Optional.of("foo is a dorkyface")));
		assertThat("incorrect disabled admin", uds3.getByAdmin(),
				is(Optional.of(new UserName("bar"))));
		TestCommon.assertDateNoOlderThan(Date.from(uds3.getTime().get()), 200);
	}
}

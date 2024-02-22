package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestRoleTest extends MongoStorageTester {
	
	private static final UUID UID = UUID.randomUUID();
	
	private final static Instant DAY1 = Instant.now().truncatedTo(ChronoUnit.MILLIS)
			.plus(1, ChronoUnit.DAYS); // mongo truncates
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void createAndGetCustomRoles() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"), DAY1);
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void updateCustomRole() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("foo", "baz"), DAY1);
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "baz"))));
	}
	
	@Test
	public void expireRole() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"), Instant.now());
		Thread.sleep(1);
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void createRoleFail() throws Exception {
		failCreateRole(null, DAY1, new NullPointerException("role"));
		failCreateRole(new CustomRole("foo", "bar"), null, new NullPointerException("expires"));
	}
	
	public void failCreateRole(
			final CustomRole role,
			final Instant expires,
			final Exception expected) {
		try {
			storage.testModeSetCustomRole(role, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getExpiry() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		assertThat("incorrect expiry", storage.testModeGetCustomRoleExpiry("foo"), is(DAY1));
	}
	
	@Test
	public void getExpiryFailInputs() {
		failGetExpiry(null, new MissingParameterException("custom role id"));
		failGetExpiry("  \n  \t  ", new MissingParameterException("custom role id"));
		failGetExpiry("foo*bar", new IllegalParameterException(
				"Illegal character in custom role id foo*bar: *"));
	}
	
	@Test
	public void getExpiryFailNoSuchRole() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		failGetExpiry("foo1", new NoSuchRoleException("foo1"));
	}
	
	private void failGetExpiry(final String roleId, final Exception expected) {
		try {
			storage.testModeGetCustomRoleExpiry(roleId);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void missingRoleInDB() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		db.getCollection("test_cust_roles").updateOne(new Document("id", "foo"),
				new Document("$set", new Document("id", "   \t    ")));
		try {
			storage.testModeGetCustomRoles();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Error in roles collection - role with illegal or missing field"));
		}
	}
	
	@Test
	public void illegalRoleInDB() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), DAY1);
		db.getCollection("test_cust_roles").updateOne(new Document("id", "foo"),
				new Document("$set", new Document("id", "foo*bar")));
		try {
			storage.testModeGetCustomRoles();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Error in roles collection - role with illegal or missing field"));
		}
	}
	
	@Test
	public void getStdRoleFromTestCollection() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"), DAY1);
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"))));
	}
	
	@Test
	public void getTestRoleFromStdCollection() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"), DAY1);
		assertThat("incorrect custom roles", storage.getCustomRoles(),
				is(set(new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void addAndRemoveRoles() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), UID, new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("baz", "bleah"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("bat", "bleah"), DAY1);
		
		storage.testModeSetRoles(new UserName("foo"), set(Role.ADMIN, Role.SERV_TOKEN),
				set("foo", "bar", "baz"));
		AuthUser u = storage.testModeGetUser(new UserName("foo"));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.SERV_TOKEN, Role.ADMIN)));
		assertThat("incorrect customroles", u.getCustomRoles(), is(set("foo", "baz", "bar")));
		
		storage.testModeSetRoles(new UserName("foo"), set(Role.DEV_TOKEN), set("bar", "bat"));
		u = storage.testModeGetUser(new UserName("foo"));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.DEV_TOKEN)));
		assertThat("incorrect roles", u.getCustomRoles(), is(set("bar", "bat")));
		
		storage.testModeSetRoles(new UserName("foo"), set(), set());
		u = storage.testModeGetUser(new UserName("foo"));
		System.out.println(u.getCustomRoles());
		assertThat("incorrect roles", u.getRoles(), is(set()));
		assertThat("incorrect roles", u.getCustomRoles(), is(set()));
	}
	
	@Test
	public void roleDeletionRace() throws Exception {
		/* Test the case where mongo or the server goes down when attempting to delete a role from
		 * users after deleting said role. 
		 * Deleting the roles from users first doesn't help because the deletion may be in
		 * progress and the role re-added to a user by another call before the role document is
		 * deleted.
		 */
		/* note that deleting custom roles is currently not supported, but we include this test
		 * case for future proofing purposes.
		 */
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), UID, new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"), DAY1);
		storage.testModeSetRoles(new UserName("foo"), set(), set("foo", "bar"));
		
		//out of band deletion, should never happen under normal conditions
		db.getCollection("test_cust_roles").deleteOne(new Document("id", "foo"));
		
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(), is(set("bar")));
	}
	
	@Test
	public void addTestRoleToStdUser() throws Exception {
		storage.setCustomRole(new CustomRole("bar", "bat"));
		storage.setCustomRole(new CustomRole("baz", "bat"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bat"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("baz", "bat"), DAY1);
		storage.createUser(NewUser.getBuilder(new UserName("foo"), UID, new DisplayName("bar"),
				Instant.ofEpochMilli(10000), REMOTE).build());
		failUpdateRoles(new UserName("foo"), set(Role.ADMIN), set("bar", "baz"),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void addStdRoleToTestUser() throws Exception {
		storage.setCustomRole(new CustomRole("bar", "bat"));
		storage.setCustomRole(new CustomRole("baz", "bat"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bat"), DAY1);
		storage.testModeSetCustomRole(new CustomRole("baz", "bat"), DAY1);
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), UID, new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		try {
			storage.updateCustomRoles(new UserName("foo"), set("bar"), set("baz"));
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NoSuchUserException("foo"));
		}
		try {
			storage.updateRoles(new UserName("foo"), set(Role.ADMIN), set(Role.CREATE_ADMIN));
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NoSuchUserException("foo"));
		}
	}
	
	@Test
	public void updateFailNulls() throws Exception {
		final UserName un = new UserName("foo");
		failUpdateRoles(null, Collections.emptySet(), Collections.emptySet(),
				new NullPointerException("userName"));
		failUpdateRoles(un, null, Collections.emptySet(), new NullPointerException("roles"));
		failUpdateRoles(un, Collections.emptySet(), null, new NullPointerException("customRoles"));
	}
	
	@Test
	public void updateFailRoot() throws Exception {
		failUpdateRoles(new UserName("foo"), set(Role.ROOT), set(),
				new IllegalArgumentException("Cannot change root role"));
	}
	
	@Test
	public void updateFailNullsInSet() throws Exception {
		final UserName un = new UserName("foo");
		failUpdateRoles(un, set(Role.ADMIN, null), Collections.emptySet(),
				new NullPointerException("Null role in roles"));
		failUpdateRoles(un, Collections.emptySet(), set("bar", null),
				new NullPointerException("Null role in customRoles"));
	}
	
	@Test
	public void updateFailNoSuchUser() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"), DAY1);
		failUpdateRoles(new UserName("foo"), set(Role.ADMIN), set("foo"),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void updateFailNoSuchRole() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), UID, new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"), DAY1);
		failUpdateRoles(new UserName("foo"), set(), set("bar"),
				new NoSuchRoleException("bar"));
	}
	
	private void failUpdateRoles(
			final UserName user,
			final Set<Role> roles,
			final Set<String> customRoles,
			final Exception e) {
		try {
			storage.testModeSetRoles(user, roles, customRoles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}

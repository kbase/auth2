package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestCustomRoleTest extends MongoStorageTester {
	
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void createAndGetCustomRoles() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"));
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"));
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void updateCustomRole() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"));
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"));
		storage.testModeSetCustomRole(new CustomRole("foo", "baz"));
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "baz"))));
	}
	
	@Test
	public void createRoleFail() throws Exception {
		try {
			storage.testModeSetCustomRole(null);
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new NullPointerException("role"));
		}
	}
	
	@Test
	public void missingRoleInDB() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"));
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
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"));
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
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"));
		assertThat("incorrect custom roles", storage.testModeGetCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"))));
	}
	
	@Test
	public void getTestRoleFromStdCollection() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.testModeSetCustomRole(new CustomRole("foo1", "bar1"));
		assertThat("incorrect custom roles", storage.getCustomRoles(),
				is(set(new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void addAndRemoveRoles() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("baz", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bat", "bleah"));
		
		storage.testModeUpdateCustomRoles(new UserName("foo"),
				set("foo", "bar", "baz"), set("bat"));
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("foo", "baz", "bar")));
		
		storage.testModeUpdateCustomRoles(new UserName("foo"), set("bat"), set("foo", "baz"));
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("bar", "bat")));
	}
	
	@Test
	public void addRoles() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		
		storage.testModeUpdateCustomRoles(
				new UserName("foo"), set("foo", "bar"), Collections.emptySet());
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("bar", "foo")));
	}
	
	@Test
	public void removeRoles() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		
		storage.testModeUpdateCustomRoles(
				new UserName("foo"), set("foo", "bar"), Collections.emptySet());
		storage.testModeUpdateCustomRoles(
				new UserName("foo"), Collections.emptySet(), set("foo", "bar"));
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void removeNonExistentRoles() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		
		storage.testModeUpdateCustomRoles(new UserName("foo"), Collections.emptySet(),
				set("foo", "bar"));
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void addAndRemoveSameRole() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		
		storage.testModeUpdateCustomRoles(new UserName("foo"), set("foo", "bar"), set("foo"));
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("bar")));
	}
	
	@Test
	public void noop() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		
		storage.testModeUpdateCustomRoles(new UserName("foo"), set("foo"), Collections.emptySet());
		
		storage.testModeUpdateCustomRoles(new UserName("foo"), Collections.emptySet(),
				Collections.emptySet());
		
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("foo")));
	}
	
	//TODO NOW expire custom roles.
	
	@Test
	public void roleDeletionRace() throws Exception {
		/* Test the case where mongo or the server goes down when attempting to delete a role from
		 * users after deleting said role. 
		 * Deleting the roles from users first doesn't help because the deletion may be in
		 * progress and the role re-added to a user by another call before the role document is
		 * deleted.
		 */
		/* note that deleting custom roles is current not supported, but we include this test
		 * case for future proofing purposes.
		 */
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bleah"));
		storage.testModeUpdateCustomRoles(new UserName("foo"), set("foo", "bar"),
				Collections.emptySet());
		
		//out of band deletion, should never happen under normal conditions
		db.getCollection("test_cust_roles").deleteOne(new Document("id", "foo"));
		
		assertThat("incorrect roles", storage.testModeGetUser(
				new UserName("foo")).getCustomRoles(),
				is(set("bar")));
	}
	
	@Test
	public void addTestRoleToStdUser() throws Exception {
		storage.setCustomRole(new CustomRole("bar", "bat"));
		storage.setCustomRole(new CustomRole("baz", "bat"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bat"));
		storage.testModeSetCustomRole(new CustomRole("baz", "bat"));
		storage.createUser(NewUser.getBuilder(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000), REMOTE).build());
		failUpdateRoles(new UserName("foo"), set("bar"), set("baz"),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void addStdRoleToTestUser() throws Exception {
		storage.setCustomRole(new CustomRole("bar", "bat"));
		storage.setCustomRole(new CustomRole("baz", "bat"));
		storage.testModeSetCustomRole(new CustomRole("bar", "bat"));
		storage.testModeSetCustomRole(new CustomRole("baz", "bat"));
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		try {
			storage.updateCustomRoles(new UserName("foo"), set("bar"), set("baz"));
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
		failUpdateRoles(un, null, Collections.emptySet(), new NullPointerException("addRoles"));
		failUpdateRoles(un, Collections.emptySet(), null, new NullPointerException("removeRoles"));
	}
	
	@Test
	public void updateFailNullsInSet() throws Exception {
		final UserName un = new UserName("foo");
		failUpdateRoles(un, set("foo", null), Collections.emptySet(),
				new NullPointerException("Null role in addRoles"));
		failUpdateRoles(un, Collections.emptySet(), set("bar", null),
				new NullPointerException("Null role in removeRoles"));
	}
	
	@Test
	public void updateFailNoSuchUser() throws Exception {
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		failUpdateRoles(new UserName("foo"), set("foo"), Collections.emptySet(),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void updateFailNoSuchRole() throws Exception {
		final Instant expires = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(100000), expires);
		storage.testModeSetCustomRole(new CustomRole("foo", "bleah"));
		failUpdateRoles(new UserName("foo"), set("foo"), set("bar"),
				new NoSuchRoleException("bar"));
		failUpdateRoles(new UserName("foo"), set("bar"), set("foo"),
				new NoSuchRoleException("bar"));
	}
	
	
	private void failUpdateRoles(
			final UserName user,
			final Set<String> addRoles,
			final Set<String> removeRoles,
			final Exception e) {
		try {
			storage.testModeUpdateCustomRoles(user, addRoles, removeRoles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}

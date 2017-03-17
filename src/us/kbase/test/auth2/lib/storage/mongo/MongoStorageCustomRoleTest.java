package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageCustomRoleTest extends MongoStorageTester {

	private static final Instant NOW = Instant.now();
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void createAndGetCustomRoles() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.setCustomRole(new CustomRole("foo1", "bar1"));
		assertThat("incorrect custom roles", storage.getCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "bar"))));
	}
	
	@Test
	public void updateCustomRole() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.setCustomRole(new CustomRole("foo1", "bar1"));
		storage.setCustomRole(new CustomRole("foo", "baz"));
		assertThat("incorrect custom roles", storage.getCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"), new CustomRole("foo", "baz"))));
	}
	
	@Test
	public void deleteCustomRole() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		storage.setCustomRole(new CustomRole("foo1", "bar1"));
		storage.deleteCustomRole("foo");
		assertThat("incorrect custom roles", storage.getCustomRoles(),
				is(set(new CustomRole("foo1", "bar1"))));
	}
	
	@Test
	public void createRoleFail() throws Exception {
		try {
			storage.setCustomRole(null);
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new NullPointerException("role"));
		}
	}
	
	@Test
	public void deleteRoleFailMissingParam() {
		failDeleteRole(null, new MissingParameterException("custom role id"));
		failDeleteRole("   \n \t   ", new MissingParameterException("custom role id"));
	}
	
	@Test
	public void deleteRoleFailIllegalRoleID() {
		failDeleteRole("foo*bar", new IllegalParameterException(
				"Illegal character in custom role id foo*bar: *"));
	}
	
	@Test
	public void deleteRoleFailNoSuchRole() {
		failDeleteRole("foo", new NoSuchRoleException("foo"));
	}
	
	private void failDeleteRole(final String roleId, final Exception e) {
		try {
			storage.deleteCustomRole(roleId);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void missingRoleInDB() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		db.getCollection("cust_roles").updateOne(new Document("id", "foo"),
				new Document("$set", new Document("id", "   \t    ")));
		try {
			storage.getCustomRoles();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Error in roles collection - role with illegal or missing field"));
		}
	}
	
	@Test
	public void illegalRoleInDB() throws Exception {
		storage.setCustomRole(new CustomRole("foo", "bar"));
		db.getCollection("cust_roles").updateOne(new Document("id", "foo"),
				new Document("$set", new Document("id", "foo*bar")));
		try {
			storage.getCustomRoles();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new AuthStorageException(
					"Error in roles collection - role with illegal or missing field"));
		}
	}
	
	@Test
	public void addAndRemoveRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		storage.setCustomRole(new CustomRole("baz", "bleah"));
		storage.setCustomRole(new CustomRole("bat", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("foo", "bar", "baz"), set("bat"));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("foo", "baz", "bar")));
		
		storage.updateCustomRoles(new UserName("foo"), set("bat"), set("foo", "baz"));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("bar", "bat")));
	}
	
	@Test
	public void addRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("foo", "bar"), Collections.emptySet());
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("bar", "foo")));
	}
	
	@Test
	public void removeRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("foo", "bar"), Collections.emptySet());
		storage.updateCustomRoles(new UserName("foo"), Collections.emptySet(), set("foo", "bar"));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void removeNonExistentRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), Collections.emptySet(),
				set("foo", "bar"));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void addAndRemoveSameRole() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("foo", "bar"), set("foo"));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("bar")));
	}
	
	@Test
	public void noop() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("foo"), Collections.emptySet());
		
		storage.updateCustomRoles(new UserName("foo"), Collections.emptySet(),
				Collections.emptySet());
		
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("foo")));
	}
	
	@Test
	public void roleDeletionRace() throws Exception {
		/* Test the case where mongo or the server goes down when attempting to delete a role from
		 * users after deleting said role. 
		 * Deleting the roles from users first doesn't help because the deletion may be in
		 * progress and the role re-added to a user by another call before the role document is
		 * deleted.
		 */
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		storage.setCustomRole(new CustomRole("bar", "bleah"));
		storage.updateCustomRoles(new UserName("foo"), set("foo", "bar"), Collections.emptySet());
		
		//out of band deletion, should never happen under normal conditions
		db.getCollection("cust_roles").deleteOne(new Document("id", "foo"));
		
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getCustomRoles(),
				is(set("bar")));
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
		storage.setCustomRole(new CustomRole("foo", "bleah"));
		failUpdateRoles(new UserName("foo"), set("foo"), Collections.emptySet(),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void updateFailNoSuchRole() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		storage.setCustomRole(new CustomRole("foo", "bleah"));
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
			storage.updateCustomRoles(user, addRoles, removeRoles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

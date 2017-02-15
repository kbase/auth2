package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageCustomRoleTest extends MongoStorageTester {

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
}

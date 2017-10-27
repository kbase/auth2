package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestCustomRoleTest extends MongoStorageTester {

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
	
}

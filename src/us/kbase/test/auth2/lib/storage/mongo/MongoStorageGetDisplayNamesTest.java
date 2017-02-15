package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageGetDisplayNamesTest extends MongoStorageTester{

	private static final RemoteIdentityWithLocalID REMOTE1 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentityWithLocalID REMOTE2 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891d56715d8"),
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	private static final RemoteIdentityWithLocalID REMOTE3 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891e56715d8"),
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));

	private static final RemoteIdentityWithLocalID REMOTE4 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891f56715d8"),
			new RemoteIdentityID("prov", "bar4"),
			new RemoteIdentityDetails("user4", "full4", "email4"));
	
	@Test
	public void getNamesFromList() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		assertThat("incorrect users found", storage.getUserDisplayNames(set(
				new UserName("foo"), new UserName("nope"), new UserName("wugga"))),
				is(expected));
	}
	
	@Test
	public void getNamesFromEmptyList() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		assertThat("incorrect users found", storage.getUserDisplayNames(
				Collections.emptySet()), is(expected));
	}
	
	@Test
	public void getNamesListFailNull() throws Exception {
		failGetNamesFromList(null, new NullPointerException("users"));
	}
	
	@Test
	public void getNamesListFailListNull() throws Exception {
		failGetNamesFromList(set(new UserName("foo"), null),
				new NullPointerException("Null username in users set"));
	}
	
	private void failGetNamesFromList(final Set<UserName> names, final Exception e) {
		try {
			storage.getUserDisplayNames(names);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void searchUserName() throws Exception {
		storage.createUser(new NewUser(new UserName("foow"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true).build(), -1, false),
				is(expected));
	}
	
	@Test
	public void searchDisplayName() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("barw"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnDisplayname(true).build(), -1, false),
				is(expected));
	}
	
	@Test
	public void searchBothNames() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		storage.createUser(new NewUser(new UserName("thewrock"), new EmailAddress("f@g.com"),
				new DisplayName("smellywcooking"), REMOTE4, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true)
				.withSearchOnDisplayname(true).build(), -1, false), is(expected));
	}
	
	@Test
	public void searchBothNamesEmpty() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		storage.createUser(new NewUser(new UserName("thewrock"), new EmailAddress("f@g.com"),
				new DisplayName("smellywcooking"), REMOTE4, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").build(), -1, false), is(expected));
	}
	
	@Test
	public void searchUserRegex() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("baz"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whoo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("baz"));
		expected.put(new UserName("whoo"), new DisplayName("bar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("^.+oo$").withSearchOnUserName(true).build(), -1, true),
				is(expected));
	}
	
	@Test
	public void searchUserLimit() throws Exception {
		storage.createUser(new NewUser(new UserName("wfoo"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		storage.createUser(new NewUser(new UserName("thewrock"), new EmailAddress("f@g.com"),
				new DisplayName("smellywcooking"), REMOTE4, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("wfoo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true).build(), 2, false), is(expected));
	}
	
	@Test
	public void searchDisplayLimit() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("whoo"), REMOTE1, null));
		storage.createUser(new NewUser(new UserName("whee"), new EmailAddress("f@g.com"),
				new DisplayName("wbar"), REMOTE2, null));
		storage.createUser(new NewUser(new UserName("wugga"), new EmailAddress("f@g.com"),
				new DisplayName("wonk"), REMOTE3, null));
		storage.createUser(new NewUser(new UserName("thewrock"), new EmailAddress("f@g.com"),
				new DisplayName("smellywcooking"), REMOTE4, null));
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnDisplayname(true).build(), 2, false),
				is(expected));
	}
	
	//TODO search on roles, some multi search tests with limits, check error conditions, no prefix, test prefix w/ regex is ignored if regex not set
}

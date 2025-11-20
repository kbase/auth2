package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserSearchSpec;
import us.kbase.auth2.lib.UserSearchSpec.Builder;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageGetDisplayNamesTest extends MongoStorageTester{
	
	private static final UUID UID1 = UUID.randomUUID();
	private static final UUID UID2 = UUID.randomUUID();
	private static final UUID UID3 = UUID.randomUUID();
	private static final UUID UID4 = UUID.randomUUID();
	private static final Instant NOW = Instant.now();
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));

	private static final RemoteIdentity REMOTE4 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar4"),
			new RemoteIdentityDetails("user4", "full4", "email4"));
	
	@Test
	public void getNamesFromList() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("bar"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("whoo"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		assertThat("incorrect users found", storage.getUserDisplayNames(set(
				new UserName("foo"), new UserName("nope"), new UserName("wugga"))),
				is(expected));
	}
	
	@Test
	public void getNamesFromEmptyList() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("bar"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("whoo"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		assertThat("incorrect users found", storage.getUserDisplayNames(
				Collections.emptySet()), is(expected));
	}
	
	@Test
	public void getNamesFromListWithDisabledUsers() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("bar"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("whoo"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		when(mockClock.instant()).thenReturn(Instant.now());
		
		storage.disableAccount(new UserName("whee"), new UserName("admin"), "they suck");
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		assertThat("incorrect users found", storage.getUserDisplayNames(set(
				new UserName("foo"), new UserName("whee"), new UserName("wugga"))),
				is(expected));
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
		storage.createUser(NewUser.getBuilder(
				new UserName("foow"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void searchDisplayName() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("barw"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void searchBothNames() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true)
				.withSearchOnDisplayName(true).build(), -1), is(expected));
	}
	
	@Test
	public void searchBothNamesEmpty() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").build(), -1), is(expected));
	}
	
	@Test
	public void searchNoResults() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("e").build(), -1), is(expected));
	}
	
	@Test
	public void searchAllResults() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		expected.put(new UserName("thewrock"), new DisplayName("smellywcooking"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(
				UserSearchSpec.getBuilder().build(), -1), is(expected));
	}
	
	@Test
	public void searchUserRegex() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("baz"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whoo"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("baz"));
		expected.put(new UserName("whoo"), new DisplayName("bar"));
		
		final Builder builder = UserSearchSpec.getBuilder();
		final Method m = Builder.class.getDeclaredMethod("withSearchRegex", String.class);
		m.setAccessible(true);
		m.invoke(builder, "^.+oo$");
		builder.withSearchOnUserName(true);
		assertThat("incorrect users found", storage.getUserDisplayNames(builder.build(), -1),
				is(expected));
	}
	
	
	@Test
	public void searchWithRegexInPrefix() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("baz"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whoo"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("^.+oo$").withSearchOnUserName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void searchUserLimit() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("wfoo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("wfoo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("bar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnUserName(true).build(), 2), is(expected));
	}
	
	@Test
	public void searchDisplayLimit() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("whoo"));
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("w").withSearchOnDisplayName(true).build(), 2),
				is(expected));
	}
	
	@Test
	public void searchRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.updateRoles(new UserName("whee"), set(Role.ADMIN, Role.DEV_TOKEN),
				Collections.emptySet());
		storage.updateRoles(new UserName("wugga"), set(Role.DEV_TOKEN), Collections.emptySet());
		storage.updateRoles(new UserName("thewrock"), set(Role.DEV_TOKEN), Collections.emptySet());
		
		//testing with a limit here isn't repeatable because it depends on the natural ordering
		// of the users, since there's no order to a set of users with the same roles 
		// can't sort on usernames since we're not indexing on usernames (not scalable in mongo)
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		expected.put(new UserName("thewrock"), new DisplayName("smellywcooking"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnRole(Role.DEV_TOKEN).build(), -1), is(expected));
	}
	
	@Test
	public void searchMultipleRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.updateRoles(new UserName("whee"), set(Role.ADMIN, Role.DEV_TOKEN),
				Collections.emptySet());
		storage.updateRoles(new UserName("wugga"), set(Role.DEV_TOKEN), Collections.emptySet());
		storage.updateRoles(new UserName("thewrock"), set(Role.DEV_TOKEN), Collections.emptySet());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnRole(Role.DEV_TOKEN).withSearchOnRole(Role.ADMIN).build(), 2),
				is(expected));
	}
	
	@Test
	public void searchCustomRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3,new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.setCustomRole(new CustomRole("baz", "bleah"));
		storage.setCustomRole(new CustomRole("bat", "bleah"));
		
		storage.updateCustomRoles(new UserName("whee"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("wugga"), set("baz"), Collections.emptySet());
		storage.updateCustomRoles(new UserName("thewrock"), set("baz"), Collections.emptySet());
		
		//testing with a limit here isn't repeatable because it depends on the natural ordering
		// of the users, since there's no order to a set of users with the same roles 
		// can't sort on usernames since we're not indexing on usernames (not scalable in mongo)
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		expected.put(new UserName("wugga"), new DisplayName("wonk"));
		expected.put(new UserName("thewrock"), new DisplayName("smellywcooking"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("baz").build(), -1), is(expected));
	}
	
	@Test
	public void searchMultipleCustomRoles() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("thewrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.setCustomRole(new CustomRole("baz", "bleah"));
		storage.setCustomRole(new CustomRole("bat", "bleah"));
		
		storage.updateCustomRoles(new UserName("whee"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("wugga"), set("baz"), Collections.emptySet());
		storage.updateCustomRoles(new UserName("thewrock"), set("baz"), Collections.emptySet());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("baz").withSearchOnCustomRole("bat").build(), 2),
				is(expected));
	}
	
	@Test
	public void searchWithDisabled() throws Exception {
		createUsersForCanonicalSearch();
		
		when(mockClock.instant()).thenReturn(Instant.now());
		
		storage.disableAccount(new UserName("u3"), new UserName("foo"), "foo");
		

		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u2"), new DisplayName("Herbert Doug~ie Howser"));
		expected.put(new UserName("u3"), new DisplayName("al douglas"));
		expected.put(new UserName("u4"), new DisplayName("Albert HevensyDouglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withIncludeDisabled(true).build(), 10), is(expected));
	}
	
	@Test
	public void searchWithoutDisabled() throws Exception {
		createUsersForCanonicalSearch();
		
		when(mockClock.instant()).thenReturn(Instant.now());
		
		storage.disableAccount(new UserName("u3"), new UserName("foo"), "foo");
		

		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u2"), new DisplayName("Herbert Doug~ie Howser"));
		expected.put(new UserName("u4"), new DisplayName("Albert HevensyDouglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withIncludeDisabled(false).build(), 10), is(expected));
	}
	
	@Test
	public void searchWithoutDisabledDefault() throws Exception {
		createUsersForCanonicalSearch();
		
		when(mockClock.instant()).thenReturn(Instant.now());
		
		storage.disableAccount(new UserName("u3"), new UserName("foo"), "foo");
		

		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u2"), new DisplayName("Herbert Doug~ie Howser"));
		expected.put(new UserName("u4"), new DisplayName("Albert HevensyDouglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.build(), 10), is(expected));
	}
	
	@Test
	public void searchFail() throws Exception {
		//only one way to actually cause an exception
		try {
			storage.getUserDisplayNames(null, -1);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect execption message", e.getMessage(), is("spec"));
		}
	}
	
	@Test
	public void searchAllFields() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("whoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.setCustomRole(new CustomRole("baz", "bleah"));
		storage.setCustomRole(new CustomRole("bat", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("whee"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("wugga"), set("baz"), Collections.emptySet());
		storage.updateCustomRoles(new UserName("wrock"), set("bat"), Collections.emptySet());
		
		storage.updateRoles(new UserName("foo"), set(Role.DEV_TOKEN), Collections.emptySet());
		storage.updateRoles(new UserName("whee"), set(Role.ADMIN, Role.DEV_TOKEN),
				Collections.emptySet());
		storage.updateRoles(new UserName("wugga"), set(Role.SERV_TOKEN), Collections.emptySet());
		storage.updateRoles(new UserName("wrock"), set(Role.DEV_TOKEN), Collections.emptySet());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("baz")
				.withSearchOnRole(Role.DEV_TOKEN)
				.withSearchPrefix("w")
				.withSearchOnUserName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void searchAllFieldsWithLimit() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("fwhoo"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("wbar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wugga"), UID3, new DisplayName("wonk"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("wrock"), UID4, new DisplayName("smellywcooking"), NOW, REMOTE4)
				.build());
		
		storage.setCustomRole(new CustomRole("baz", "bleah"));
		storage.setCustomRole(new CustomRole("bat", "bleah"));
		
		storage.updateCustomRoles(new UserName("foo"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("whee"), set("baz", "bat"),
				Collections.emptySet());
		storage.updateCustomRoles(new UserName("wugga"), set("baz"), Collections.emptySet());
		storage.updateCustomRoles(new UserName("wrock"), set("bat"), Collections.emptySet());
		
		storage.updateRoles(new UserName("foo"), set(Role.DEV_TOKEN), Collections.emptySet());
		storage.updateRoles(new UserName("whee"), set(Role.ADMIN, Role.DEV_TOKEN),
				Collections.emptySet());
		storage.updateRoles(new UserName("wugga"), set(Role.DEV_TOKEN, Role.SERV_TOKEN),
				Collections.emptySet());
		storage.updateRoles(new UserName("wrock"), set(Role.DEV_TOKEN), Collections.emptySet());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("wbar"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchOnCustomRole("baz")
				.withSearchOnRole(Role.DEV_TOKEN)
				.withSearchPrefix("w")
				.withSearchOnDisplayName(true).build(), 1),
				is(expected));
	}
	
	@Test
	public void canonicalSearchPunctuation1() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"),
				NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("*&wbar#@  *&wh+oo;; "), NOW, REMOTE2)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"));
		expected.put(new UserName("whee"), new DisplayName("*&wbar#@  *&wh+oo;; "));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("wh+").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearchPunctuation2() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"),
				NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("*&wbar#@  *&wh+oo;; "), NOW, REMOTE2)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("wh+e").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearchPunctuation3() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"),
				NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("*&wbar#@  *&wh+oo;; "), NOW, REMOTE2)
				.build());
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("whee"), new DisplayName("*&wbar#@  *&wh+oo;; "));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("wh+o").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearchPunctuation4() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID1, new DisplayName("(wh+ee) ++bun+k]՞ fwhoo"),
				NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("whee"), UID2, new DisplayName("*&wbar#@  wh+oo;; "), NOW, REMOTE2)
				.build());
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("fwhe").withSearchOnDisplayName(true).build(), -1),
				is(Collections.emptyMap()));
	}
	
	@Test
	public void userSearchUnderscore() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo_bar"), UID1, new DisplayName("1"),
				NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("fo_obar"), UID2, new DisplayName("2"), NOW, REMOTE2)
				.build());
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("fo_").build(), -1),
				is(ImmutableMap.of(new UserName("fo_obar"), new DisplayName("2"))));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("foo_b").build(), -1),
				is(ImmutableMap.of(new UserName("foo_bar"), new DisplayName("1"))));
	}
	
	@Test
	public void canonicalSearch1() throws Exception {
		createUsersForCanonicalSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u2"), new DisplayName("Herbert Doug~ie Howser"));
		expected.put(new UserName("u3"), new DisplayName("al douglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("Doug").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearch2() throws Exception {
		createUsersForCanonicalSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u3"), new DisplayName("al douglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("Douglas").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearch3() throws Exception {
		createUsersForCanonicalSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u3"), new DisplayName("al douglas"));
		expected.put(new UserName("u4"), new DisplayName("Albert HevensyDouglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("Al").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearch4() throws Exception {
		createUsersForCanonicalSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u4"), new DisplayName("Albert HevensyDouglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("Alb").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalSearchMultitokenAndPunctuation() throws Exception {
		createUsersForCanonicalSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("u1"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("u3"), new DisplayName("al douglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("D'oug A*").withSearchOnDisplayName(true).build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalAndUserMultitokenSearch1() throws Exception {
		createUsersForCanonicalAndUserSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("adamsly"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("adamsly2"), new DisplayName("Herbert Doug~ie Howser"));
		expected.put(new UserName("ada"), new DisplayName("al douglas"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("ada*").build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalAndUserMultitokenSearch2() throws Exception {
		createUsersForCanonicalAndUserSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("adamsly"), new DisplayName("Dou*glas J Ad()ams"));
		expected.put(new UserName("adamsly2"), new DisplayName("Herbert Doug~ie Howser"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("a'dams").build(), -1),
				is(expected));
	}
	
	@Test
	public void canonicalAndUserMultitokenSearch3() throws Exception {
		createUsersForCanonicalAndUserSearch();
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("adamsly"), new DisplayName("Dou*glas J Ad()ams"));
		
		assertThat("incorrect users found", storage.getUserDisplayNames(UserSearchSpec.getBuilder()
				.withSearchPrefix("ada* Dougl").build(), -1),
				is(expected));
	}
	
	private void createUsersForCanonicalAndUserSearch() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("adamsly"), UID1, new DisplayName("Dou*glas J Ad()ams"), NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("adamsly2"), UID2, new DisplayName("Herbert Doug~ie Howser"),
				NOW, REMOTE2)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("ada"), UID3, new DisplayName("al douglas"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("adlbert"), UID4, new DisplayName("Albert HevensyDouglas"),
				NOW, REMOTE4)
				.build());
	}

	private void createUsersForCanonicalSearch() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("u1"), UID1, new DisplayName("Dou*glas J Ad()ams"), NOW, REMOTE1)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("u2"), UID2, new DisplayName("Herbert Doug~ie Howser"), NOW, REMOTE2)
				.build());
		storage.createUser(NewUser.getBuilder(
				new UserName("u3"), UID3, new DisplayName("al douglas"), NOW, REMOTE3).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("u4"), UID4, new DisplayName("Albert HevensyDouglas"), NOW, REMOTE4)
				.build());
	}
}

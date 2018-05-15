package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestGetDisplayNamesTest extends MongoStorageTester {
	
	@Test
	public void emptyList() throws Exception {
		final Instant now = Instant.now();
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"), now,
				now.plusSeconds(10));
		
		final Map<UserName, DisplayName> res = storage.testModeGetUserDisplayNames(set());

		assertThat("incorrect names", res, is(Collections.emptyMap()));
	}
	
	@Test
	public void getDisplayNames() throws Exception {
		final Instant now = Instant.now();
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"), now,
				now.plusSeconds(10));
		storage.testModeCreateUser(new UserName("baz"), new DisplayName("bat"), now,
				now.plusSeconds(10));
		storage.testModeCreateUser(new UserName("wugga"), new DisplayName("whoo"), now,
				now.plusSeconds(10));
		
		final Map<UserName, DisplayName> res = storage.testModeGetUserDisplayNames(
				set(new UserName("foo"), new UserName("wugga")));
		
		assertThat("incorrect names", res, is(ImmutableMap.of(
				new UserName("foo"), new DisplayName("bar"),
				new UserName("wugga"), new DisplayName("whoo"))));
	}
	
	@Test
	public void getDisplayNamesFail() throws Exception {
		failGetDisplayNames(null, new NullPointerException("users"));
		failGetDisplayNames(set(new UserName("foo"), null),
				new NullPointerException("Null username in users set"));
	}
	
	private void failGetDisplayNames(final Set<UserName> users, final Exception expected) {
		try {
			storage.testModeGetUserDisplayNames(users);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getStdNameFromTestStorage() throws Exception {
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(10000L)).build(),
				new PasswordHashAndSalt("foobarbazbat".getBytes(), "bar".getBytes()));
		
		final Map<UserName, DisplayName> res = storage.testModeGetUserDisplayNames(
				set(new UserName("foo")));

		assertThat("incorrect names", res, is(Collections.emptyMap()));
	}
	
	@Test
	public void getTestNameFromStdStorage() throws Exception {
		final Instant now = Instant.now();
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"), now,
				now.plusSeconds(10));
		
		final Map<UserName, DisplayName> res = storage.getUserDisplayNames(
				set(new UserName("foo")));

		assertThat("incorrect names", res, is(Collections.emptyMap()));
	}

}

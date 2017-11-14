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

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestUserCreateGetTest extends MongoStorageTester {
	
	/* we test clearing of all data here, since it has to be somewhere. */
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

	@Test
	public void clearTestData() throws Exception {
		final Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000), expiry);
		
		storage.testModeSetCustomRole(new CustomRole("foo", "bar"), expiry);
		
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken store = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(store, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");

		final AuthUser u = storage.testModeGetUser(new UserName("foo"));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		
		final StoredToken t = storage.testModeGetToken(
				new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token name", t.getTokenName(),
				is(Optional.of(new TokenName("foo"))));
		
		final Set<CustomRole> roles = storage.testModeGetCustomRoles();
		assertThat("incorrect roles", roles, is(set(new CustomRole("foo", "bar"))));
		
		storage.testModeClear();
		
		failGetUser(new UserName("foo"), new NoSuchUserException("foo"));
		
		try {
			storage.testModeGetToken(new IncomingToken("sometoken").getHashedToken());
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NoSuchTokenException("Token not found"));
		}
		
		assertThat("incorrect roles", storage.testModeGetCustomRoles(), is(set()));
	}
	
	@Test
	public void createAndGet() throws Exception {
		final Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("foo"), new DisplayName("bar"),
				Instant.ofEpochMilli(10000), expiry);
		
		final Instant e = storage.testModeGetUserExpiry(new UserName("foo"));
		assertThat("incorrect expiry", e, is(expiry));
		
		final AuthUser u = storage.testModeGetUser(new UserName("foo"));
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect creation", u.getCreated(), is(Instant.ofEpochMilli(10000)));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set()));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getNullUser() {
		failGetUser(null, new NullPointerException("userName"));
		failGetUserExpiry(null, new NullPointerException("userName"));
	}
	
	@Test
	public void getNoSuchUser() throws Exception {
		final Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("user1"), new DisplayName("bar1"),
				Instant.ofEpochMilli(10000), expiry);

		failGetUser(new UserName("user2"), new NoSuchUserException("user2"));
		failGetUserExpiry(new UserName("user2"), new NoSuchUserException("user2"));
	}
	
	@Test
	public void getStdUserFromTestCollection() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user"), new DisplayName("bar"), Instant.now(), REMOTE1)
				.build());
		
		failGetUser(new UserName("user"), new NoSuchUserException("user"));
	}
	
	@Test
	public void getTestUserFromStdCollection() throws Exception {
		final Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("user1"), new DisplayName("bar1"),
				Instant.ofEpochMilli(10000), expiry);
		
		try {
			storage.getUser(new UserName("user1"));
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NoSuchUserException("user1"));
		}
	}
	
	@Test
	public void getExpiredUser() throws Exception {
		// this test could fail to cover the intended code if mongo happens to remove the user
		// before the get occurs.
		// since the removal thread only runs 1/min should be rare.
		storage.testModeCreateUser(new UserName("user1"), new DisplayName("bar1"),
				Instant.ofEpochMilli(10000), Instant.now());
		Thread.sleep(1);
		failGetUser(new UserName("user1"), new NoSuchUserException("user1"));
	}
	
	private void failGetUser(final UserName user, final Exception e) {
		try {
			storage.testModeGetUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetUserExpiry(final UserName user, final Exception e) {
		try {
			storage.testModeGetUserExpiry(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void createUserBadArgsFail() throws Exception {
		final UserName u = new UserName("foo");
		final DisplayName n = new DisplayName("bar");
		final Instant c = Instant.ofEpochMilli(1000);
		final Instant e = Instant.now().plus(1, ChronoUnit.DAYS);
		
		failCreateuser(null, n, c, e, new NullPointerException("name"));
		failCreateuser(UserName.ROOT, n, c, e,
				new IllegalArgumentException("Test users cannot be root"));
		failCreateuser(u, null, c, e, new NullPointerException("display"));
		failCreateuser(u, n, null, e, new NullPointerException("created"));
		failCreateuser(u, n, c, null, new NullPointerException("expires"));
	}
	
	@Test
	public void createUserDuplicateFail() throws Exception {
		final Instant expiry = Instant.now().plus(1, ChronoUnit.DAYS);
		storage.testModeCreateUser(new UserName("user1"), new DisplayName("bar1"),
				Instant.ofEpochMilli(10000), expiry);
		
		failCreateuser(new UserName("user1"), new DisplayName("whee"),
				Instant.ofEpochMilli(100000), expiry.plus(3, ChronoUnit.MINUTES),
				new UserExistsException("user1"));
	}
	
	private void failCreateuser(
			final UserName name,
			final DisplayName display,
			final Instant created,
			final Instant expires,
			final Exception expected) {
		try {
			storage.testModeCreateUser(name, display, created, expires);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
}

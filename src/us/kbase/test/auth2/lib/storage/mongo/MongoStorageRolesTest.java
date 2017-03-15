package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageRolesTest extends MongoStorageTester {

	private static final Instant NOW = Instant.now();
	
	private static final Set<PolicyID> MTPID = Collections.emptySet();
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void addAndRemoveRoles() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		
		storage.updateRoles(new UserName("foo"),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN, Role.ADMIN), set(Role.SERV_TOKEN));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(set(Role.ADMIN, Role.CREATE_ADMIN, Role.DEV_TOKEN)));
		
		storage.updateRoles(new UserName("foo"), set(Role.SERV_TOKEN),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(set(Role.ADMIN, Role.SERV_TOKEN)));
	}
	
	@Test
	public void addRoles() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		storage.updateRoles(new UserName("foo"), set(Role.DEV_TOKEN, Role.ADMIN),
				Collections.emptySet());
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(set(Role.ADMIN, Role.DEV_TOKEN)));
	}
	
	@Test
	public void removeRoles() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		
		storage.updateRoles(new UserName("foo"),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN), Collections.emptySet());
		storage.updateRoles(new UserName("foo"), Collections.emptySet(),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void removeNonExistentRoles() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		
		storage.updateRoles(new UserName("foo"), Collections.emptySet(),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(Collections.emptySet()));
	}
	
	@Test
	public void addAndRemoveSameRole() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		
		storage.updateRoles(new UserName("foo"),
				set(Role.DEV_TOKEN, Role.CREATE_ADMIN), set(Role.DEV_TOKEN));
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(set(Role.CREATE_ADMIN)));
	}
	
	@Test
	public void noop() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		storage.updateRoles(new UserName("foo"), set(Role.DEV_TOKEN), Collections.emptySet());
		
		storage.updateRoles(new UserName("foo"), Collections.emptySet(), Collections.emptySet());
		
		assertThat("incorrect roles", storage.getUser(new UserName("foo")).getRoles(),
				is(set(Role.DEV_TOKEN)));
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
		failUpdateRoles(un, set(Role.ADMIN, null), Collections.emptySet(),
				new NullPointerException("Null role in addRoles"));
		failUpdateRoles(un, Collections.emptySet(), set(Role.ADMIN, null),
				new NullPointerException("Null role in removeRoles"));
	}
	
	@Test
	public void updateFailNoSuchUser() throws Exception {
		failUpdateRoles(new UserName("foo"), set(Role.ADMIN), Collections.emptySet(),
				new NoSuchUserException("foo"));
	}
	
	@Test
	public void updateFailSetRoot() throws Exception {
		final UserName un = new UserName("foo");
		failUpdateRoles(un, set(Role.ROOT, Role.DEV_TOKEN), Collections.emptySet(),
				new IllegalArgumentException("Cannot change root role"));
		failUpdateRoles(un, Collections.emptySet(), set(Role.ROOT, Role.DEV_TOKEN),
				new IllegalArgumentException("Cannot change root role"));
	}
	
	private void failUpdateRoles(
			final UserName user,
			final Set<Role> addRoles,
			final Set<Role> removeRoles,
			final Exception e) {
		try {
			storage.updateRoles(user, addRoles, removeRoles);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}	

package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageLinkTest extends MongoStorageTester {

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
	public void link() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void unlink() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		storage.unlink(new UserName("foo"), REMOTE1.getRemoteID().getID());
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE2)));
	}
	
	@Test
	public void linkNoop() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));
		storage.link(new UserName("foo"), ri); // noop
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void linkAndUpdateIdentity() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user10", "full10", "email10"));
		storage.link(new UserName("foo"), ri);
		
		final RemoteIdentity expected = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user10", "full10", "email10"));
		
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(expected, REMOTE1)));
	}
	
	@Test
	public void linkReflectionPass() throws Exception {
		final Method m = MongoStorage.class.getDeclaredMethod(
				"addIdentity", AuthUser.class, RemoteIdentity.class);
		m.setAccessible(true);
		
		storage.createUser(NewUser.getBuilder(
				new UserName("foo1"), new DisplayName("bar"), NOW, REMOTE4).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		final AuthUser au = storage.getUser(new UserName("foo"));
		final boolean p = (boolean) m.invoke(storage, au, REMOTE2);
		assertThat("expected successful link", p, is(true));
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE1, REMOTE2)));
	}
	
	@Test
	public void linkReflectionAddIDFail() throws Exception {
		/* This tests the case where an id to be linked is added after pulling the user but before
		 * the target id is linked. The link should therefore fail.
		 */
		final Method m = MongoStorage.class.getDeclaredMethod(
				"addIdentity", AuthUser.class, RemoteIdentity.class);
		m.setAccessible(true);
		storage.createUser(NewUser.getBuilder(
				new UserName("foo1"), new DisplayName("bar"), NOW, REMOTE4).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		final AuthUser au = storage.getUser(new UserName("foo"));
		storage.link(new UserName("foo"), REMOTE2);
		
		final RemoteIdentity ri = new RemoteIdentity(REMOTE2.getRemoteID(),
				new RemoteIdentityDetails("reflectfail1", "reflectfail2", "fail@fail.com"));
		
		final boolean p = (boolean) m.invoke(storage, au, ri);
		assertThat("expected failed link", p, is(false));
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE1, REMOTE2)));
	}
	
	@Test
	public void linkReflectionAddIDPass() throws Exception {
		/* This tests the case where a different id is linked after pulling the user but before
		 * the target id is linked. The link should therefore succeed.
		 */
		final Method m = MongoStorage.class.getDeclaredMethod(
				"addIdentity", AuthUser.class, RemoteIdentity.class);
		m.setAccessible(true);
		storage.createUser(NewUser.getBuilder(
				new UserName("foo1"), new DisplayName("bar"), NOW, REMOTE4).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		final AuthUser au = storage.getUser(new UserName("foo"));
		storage.link(new UserName("foo"), REMOTE2);
		
		final boolean p = (boolean) m.invoke(storage, au, REMOTE3);
		assertThat("expected failed link", p, is(true));
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE1, REMOTE2, REMOTE3)));
	}
	
	@Test
	public void linkReflectionRemoveID() throws Exception {
		/* This tests the case where a user's identities are changed between pulling the user from
		 * the db and running the link. Expected to pass if an ID is removed.
		 */
		final Method m = MongoStorage.class.getDeclaredMethod(
				"addIdentity", AuthUser.class, RemoteIdentity.class);
		m.setAccessible(true);
		storage.createUser(NewUser.getBuilder(
				new UserName("foo1"), new DisplayName("bar"), NOW, REMOTE4).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		final AuthUser au = storage.getUser(new UserName("foo"));
		storage.unlink(new UserName("foo"), REMOTE1.getRemoteID().getID());
		final boolean p = (boolean) m.invoke(storage, au, REMOTE3);
		assertThat("expected failed link", p, is(true));
		assertThat("incorrect identities", storage.getUser(new UserName("foo")).getIdentities(),
				is(set(REMOTE2, REMOTE3)));
	}
	
	@Test
	public void linkFailNulls() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		failLink(null, REMOTE1, new NullPointerException("userName"));
		failLink(new UserName("foo"), null, new NullPointerException("remoteID"));
	}
	
	@Test
	public void linkFailNoUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		failLink(new UserName("foo1"), REMOTE2, new NoSuchUserException("foo1"));
	}
	
	@Test
	public void linkFailLocalUser() throws Exception {
		final byte[] pwd = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whee".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("local"), new DisplayName("bar"), NOW, pwd, salt).build();
				
		storage.createLocalUser(nlu);
		failLink(new UserName("local"), REMOTE2,
				new LinkFailedException("Cannot link identities to a local user"));
	}
	
	@Test
	public void linkFailAlreadyLinked() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo2"), new DisplayName("bar"), NOW, REMOTE1).build());
		
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user10", "full10", "email10"));
		failLink(new UserName("foo2"), ri,
				new LinkFailedException("Provider identity is already linked"));
	}
	
	private void failLink(
			final UserName name,
			final RemoteIdentity id,
			final Exception e) {
		try {
			storage.link(name, id);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void unlinkFailInput() throws Exception {
		failUnlink(null, "foobar", new NullPointerException("userName"));
		failUnlink(new UserName("foo"), null,
				new IllegalArgumentException("Missing argument: id"));
		failUnlink(new UserName("foo"), "    \t \n   ",
				new IllegalArgumentException("Missing argument: id"));
	}
	
	@Test
	public void unlinkFailNoUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		failUnlink(new UserName("foo1"), REMOTE1.getRemoteID().getID(),
				new NoSuchUserException("foo1"));
	}
	
	@Test
	public void unlinkFailLocalUser() throws Exception {
		final byte[] pwd = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whee".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("local"), new DisplayName("bar"), NOW, pwd, salt).build();
				
		storage.createLocalUser(nlu);
		failUnlink(new UserName("local"), "foobar",
				new UnLinkFailedException("Local users have no identities"));
	}
	
	@Test
	public void unlinkFailOneIdentity() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		failUnlink(new UserName("foo"), REMOTE1.getRemoteID().getID(),
				new UnLinkFailedException("The user has only one associated identity"));
	}
	
	@Test
	public void unlinkFailNoSuchIdentity() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
		storage.link(new UserName("foo"), REMOTE2);
		storage.createUser(NewUser.getBuilder(
				new UserName("foo1"), new DisplayName("bar"), NOW, REMOTE3).build());
		failUnlink(new UserName("foo"), REMOTE3.getRemoteID().getID(),
				new NoSuchIdentityException("The user is not linked to identity " +
						REMOTE3.getRemoteID().getID()));
	}
	
	private void failUnlink(final UserName name, final String id, final Exception e) {
		try {
			storage.unlink(name, id);
			fail("exception expected");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

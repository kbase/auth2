package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class AuthUserTest {
	
	private static final Date NOW = new Date();
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void constructMinimal() throws Exception {
		final AuthUser u = new AuthUserSuppliedCRoles(new UserName("foo"),
				new EmailAddress("f@g.com"), new DisplayName("bar"), null,
				null, null, NOW, null, new UserDisabledState());
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is((Set<String>) null));
		assertThat("incorrect disabled state", u.getDisabledState().getByAdmin(),
				is((UserName) null));
		assertThat("incorrect disabled state", u.getDisabledState().getDisabledReason(),
				is((String) null));
		assertThat("incorrect disabled state", u.getDisabledState().getTime(), is((Date) null));
		assertThat("incorrect disabled state", u.getDisabledState().isDisabled(), is(false));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", u.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void constructWithRoot() throws Exception {
		final Date ll = new Date();
		Thread.sleep(2);
		final Date d = new Date();
		
		final AuthUser u = new AuthUserSuppliedCRoles(UserName.ROOT,
				new EmailAddress("f@g1.com"), new DisplayName("bar1"), null,
				set(Role.ROOT), set("foo", "bar"), NOW, ll, new UserDisabledState(
						"reason", new UserName("whee"), d));
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(new UserName("whee")));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("bar", "foo")));
		assertThat("incorrect disabled state", u.getDisabledState().getByAdmin(),
				is(new UserName("whee")));
		assertThat("incorrect disabled state", u.getDisabledState().getDisabledReason(),
				is("reason"));
		assertThat("incorrect disabled state", u.getDisabledState().getTime(), is(d));
		assertThat("incorrect disabled state", u.getDisabledState().isDisabled(), is(true));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@g1.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(d));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is("reason"));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.ROOT)));
		assertThat("incorrect user name", u.getUserName(), is(UserName.ROOT));
		assertThat("incorrect is disabled", u.isDisabled(), is(true));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(true));
	}
	
	@Test
	public void constructMaximal() throws Exception {
		final Date ll = new Date();
		Thread.sleep(2);
		final Date d = new Date();
		
		final AuthUser u = new AuthUserSuppliedCRoles(new UserName("whoo"),
				new EmailAddress("f@g2.com"), new DisplayName("bar3"), set(REMOTE),
				set(Role.DEV_TOKEN, Role.SERV_TOKEN), set("foo1"), NOW, ll, new UserDisabledState(
						new UserName("whee1"), d));
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(new UserName("whee1")));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("foo1")));
		assertThat("incorrect disabled state", u.getDisabledState().getByAdmin(),
				is(new UserName("whee1")));
		assertThat("incorrect disabled state", u.getDisabledState().getDisabledReason(),
				is((String) null));
		assertThat("incorrect disabled state", u.getDisabledState().getTime(), is(d));
		assertThat("incorrect disabled state", u.getDisabledState().isDisabled(), is(false));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar3")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@g2.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(d));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("whoo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void roleMethods() throws Exception {
		final AuthUser u = new AuthUserSuppliedCRoles(new UserName("whoo"),
				new EmailAddress("f@g2.com"), new DisplayName("bar3"), null, 
				set(Role.ADMIN, Role.DEV_TOKEN), null, NOW, null,
				new UserDisabledState());
		
		assertThat("incorrect has role", u.hasRole(Role.ROOT), is(false));
		assertThat("incorrect has role", u.hasRole(Role.CREATE_ADMIN), is(false));
		assertThat("incorrect has role", u.hasRole(Role.ADMIN), is(true));
		assertThat("incorrect has role", u.hasRole(Role.SERV_TOKEN), is(false));
		assertThat("incorrect has role", u.hasRole(Role.DEV_TOKEN), is(true));
		
		assertThat("incorrect canGrant", u.getGrantableRoles(),
				is(set(Role.DEV_TOKEN, Role.SERV_TOKEN)));
	}
	
	@Test
	public void getIdentity() throws Exception {
		final RemoteIdentityWithLocalID ri2 = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56714d8"),
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));
		
		final AuthUser u = new AuthUserSuppliedCRoles(new UserName("whoo"),
				new EmailAddress("f@g2.com"), new DisplayName("bar3"), set(REMOTE, ri2),
				null, null, NOW, null, new UserDisabledState());
		
		final RemoteIdentity target = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user6", "full6", "email6"));
		
		assertThat("incorrect identity", u.getIdentity(target), is(ri2));
		
		final RemoteIdentity target2 = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar1"),
				new RemoteIdentityDetails("user6", "full6", "email6"));
		
		assertThat("incorrect identity", u.getIdentity(target2), is(REMOTE));
		
		final RemoteIdentity target3 = new RemoteIdentity(
				new RemoteIdentityID("prov1", "bar1"),
				new RemoteIdentityDetails("user6", "full6", "email6"));
		
		assertThat("incorrect identity", u.getIdentity(target3),
				is((RemoteIdentityWithLocalID) null));
	}
	
	@Test
	public void lastLogin() throws Exception {
		final Date ll = new Date();
		Thread.sleep(2);
		final Date c = new Date();
		final AuthUser u = new AuthUserSuppliedCRoles(new UserName("foo"),
				new EmailAddress("f@g.com"), new DisplayName("bar"), null,
				null, null, c, ll, new UserDisabledState());
		assertThat("last login not updated correctly", u.getLastLogin(), is(c));
	}
	
	@Test
	public void constructFail() throws Exception {
		final UserName un = new UserName("foo");
		final EmailAddress email = new EmailAddress("f@g.com");
		final DisplayName dn = new DisplayName("bar");
		final Set<RemoteIdentityWithLocalID> ids = set(REMOTE);
		final Set<Role> roles = Collections.emptySet();
		final Date created = new Date();
		final UserDisabledState ds = new UserDisabledState();
		failConstruct(null, email, dn, ids, roles, created, ds,
				new NullPointerException("userName"));
		failConstruct(un, null, dn, ids, roles, created, ds,
				new NullPointerException("email"));
		failConstruct(un, email, null, ids, roles, created, ds,
				new NullPointerException("displayName"));
		failConstruct(un, email, dn, ids, roles, null, ds,
				new NullPointerException("created"));
		failConstruct(un, email, dn, ids, roles, created, null,
				new NullPointerException("disabledState"));
		failConstruct(UserName.ROOT, email, dn, null, roles, created, ds,
				new IllegalStateException("Root username must only have the ROOT role"));
		failConstruct(UserName.ROOT, email, dn, null, set(Role.ADMIN), created, ds,
				new IllegalStateException("Root username must only have the ROOT role"));
		failConstruct(UserName.ROOT, email, dn, null, set(Role.ADMIN, Role.ROOT), created, ds,
				new IllegalStateException("Root username must only have the ROOT role"));
		failConstruct(UserName.ROOT, email, dn, ids, set(Role.ROOT), created, ds,
				new IllegalStateException("Root user cannot have identities"));
		failConstruct(un, email, dn, ids, set(Role.ADMIN, Role.ROOT), created, ds,
				new IllegalStateException("Non-root username with root role"));
		failConstruct(un, email, dn, set(REMOTE, null), roles, created, ds,
				new NullPointerException("null item in identities"));
		failConstruct(un, email, dn, ids, set(Role.ADMIN, null), created, ds,
				new NullPointerException("null item in roles"));
	}
	
	private void failConstruct(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Set<RemoteIdentityWithLocalID> identities,
			final Set<Role> roles,
			final Date created,
			final UserDisabledState disabledState,
			final Exception e) {
		try {
			new AuthUserSuppliedCRoles(userName, email, displayName, identities, roles,
					Collections.emptySet(), created, null, disabledState);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}

package us.kbase.test.auth2.lib.user;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Optional;
import java.util.UUID;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;

public class AuthUserTest {
	
	private static final UUID UID = UUID.randomUUID();
	private static final Instant NOW = Instant.now();
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(AuthUser.class).usingGetClass()
				.withIgnoredFields("canGrantRoles").verify();
	}
	
	@Test
	public void constructMinimal() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), NOW)
				.build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.empty()));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.empty()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.empty()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void constructWithRoot() throws Exception {
		// also tests disabled
		final Optional<Instant> ll = Optional.of(Instant.now());
		final Instant d = ll.get().plusMillis(2);
		
		final AuthUser u = AuthUser.getBuilder(UserName.ROOT, UID, new DisplayName("bar1"), NOW)
				.withEmailAddress(new EmailAddress("f@h1.com"))
				.withCustomRole("foo")
				.withCustomRole("bar")
				.withLastLogin(ll.get())
				.withUserDisabledState(
						new UserDisabledState("reason", new UserName("whee"), d)).build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("whee"))));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("bar", "foo")));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState(
				"reason", new UserName("whee"), d)));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@h1.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.of(d)));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(),
				is(Optional.of("reason")));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.ROOT)));
		assertThat("incorrect user name", u.getUserName(), is(UserName.ROOT));
		assertThat("incorrect is disabled", u.isDisabled(), is(true));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(true));
	}
	
	@Test
	public void constructMaximal() throws Exception {
		final Optional<Instant> ll = Optional.of(Instant.now());
		final Instant d = ll.get().plusMillis(2);
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withEmailAddress(new EmailAddress("f@h2.com"))
				.withIdentity(REMOTE)
				.withRole(Role.DEV_TOKEN)
				.withRole(Role.SERV_TOKEN)
				.withCustomRole("foo1")
				.withCustomRole("bar1")
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(30000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(40000))
				.withLastLogin(ll.get())
				.withUserDisabledState(new UserDisabledState(new UserName("whee1"), d))
				.build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("whee1"))));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("bar1", "foo1")));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState(
				new UserName("whee1"), d)));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar3")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@h2.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.of(d)));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(ImmutableMap.of(
				new PolicyID("bar"), Instant.ofEpochMilli(40000),
				new PolicyID("foo"), Instant.ofEpochMilli(30000))));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("whoo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void newIdentitiesMinimal() throws Exception {
		final AuthUser pre = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withIdentity(REMOTE).build();
		
		final RemoteIdentity ri2 = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));

		final AuthUser u = AuthUser.getBuilderWithoutIdentities(pre)
				.withIdentity(ri2).build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.empty()));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar3")));
		assertThat("incorrect email", u.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.empty()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(ri2)));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.empty()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("whoo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void newIdentitiesMaximal() throws Exception {
		final Optional<Instant> ll = Optional.of(Instant.now());
		final Instant d = ll.get().plusMillis(2);
		
		final AuthUser pre = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withEmailAddress(new EmailAddress("f@h2.com"))
				.withIdentity(REMOTE)
				.withRole(Role.DEV_TOKEN)
				.withRole(Role.SERV_TOKEN)
				.withCustomRole("foo1")
				.withCustomRole("bar1")
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(30000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(40000))
				.withLastLogin(ll.get())
				.withUserDisabledState(new UserDisabledState(new UserName("whee1"), d))
				.build();
		
		final RemoteIdentity ri2 = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));
		
		final AuthUser u = AuthUser.getBuilderWithoutIdentities(pre)
				.withIdentity(ri2).build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("whee1"))));
		assertThat("incorrect created date", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("bar1", "foo1")));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState(
				new UserName("whee1"), d)));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar3")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@h2.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.of(d)));
		assertThat("incorrect grantable roles", u.getGrantableRoles(), is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(ri2)));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(ImmutableMap.of(
				new PolicyID("bar"), Instant.ofEpochMilli(40000),
				new PolicyID("foo"), Instant.ofEpochMilli(30000))));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("whoo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void roleMethods() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withRole(Role.ADMIN)
				.withRole(Role.DEV_TOKEN)
				.build();
		
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
		final RemoteIdentity ri2 = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));
		
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withIdentity(REMOTE)
				.withIdentity(ri2)
				.build();
		
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
				is((RemoteIdentity) null));
	}
	
	@Test
	public void lastLogin() throws Exception {
		final Instant ll = Instant.now();
		final Instant c = ll.plusMillis(1000);
		
		final AuthUser u = AuthUser.getBuilder(new UserName("foo"), UID, new DisplayName("bar"), c)
				.withLastLogin(ll)
				.build();
		
		assertThat("last login not updated correctly", u.getLastLogin(), is(Optional.of(c)));
	}
	
	@Test
	public void rootAddRoot() throws Exception {
		AuthUser.getBuilder(UserName.ROOT, UID, new DisplayName("foo"), NOW)
				.withRole(Role.ROOT).build();
		// should work
	}
	
	@Test
	public void constructFail() throws Exception {
		final UserName un = new UserName("foo");
		final UUID ui = UUID.randomUUID();
		final EmailAddress email = new EmailAddress("f@h.com");
		final DisplayName dn = new DisplayName("bar");
		final RemoteIdentity id = REMOTE;
		final Role role = Role.DEV_TOKEN;
		final String crole = "foobar";
		final PolicyID pid = new PolicyID("foo");
		final Instant pidt = Instant.now();
		final Instant created = Instant.now();
		final Instant ll = Instant.now();
		final UserDisabledState ds = new UserDisabledState();
		failBuild(null, ui, dn, created, email, id, role, crole, pid, pidt, ll, ds,
				new NullPointerException("userName"));
		failBuild(un, null, dn, created, email, id, role, crole, pid, pidt, ll, ds,
				new NullPointerException("anonymousID"));
		failBuild(un, ui, null, created, email, id, role, crole, pid, pidt, ll, ds,
				new NullPointerException("displayName"));
		failBuild(un, ui, dn, null, email, id, role, crole, pid, pidt, ll, ds,
				new NullPointerException("created"));
		failBuild(un, ui, dn, created, null, id, role, crole, pid, pidt, ll, ds,
				new NullPointerException("email"));
		failBuild(un, ui, dn, created, email, null, role, crole, pid, pidt, ll, ds,
				new NullPointerException("remoteIdentity"));
		failBuild(un, ui, dn, created, email, id, null, crole, pid, pidt, ll, ds,
				new NullPointerException("role"));
		failBuild(un, ui, dn, created, email, id, role, null, pid, pidt, ll, ds,
				new NullPointerException("customRole"));
		failBuild(un, ui, dn, created, email, id, role, crole, null, pidt, ll, ds,
				new NullPointerException("policyID"));
		failBuild(un, ui, dn, created, email, id, role, crole, pid, null, ll, ds,
				new NullPointerException("agreedOn"));
		failBuild(un, ui, dn, created, email, id, role, crole, pid, pidt, null, ds,
				new NullPointerException("lastLogin"));
		failBuild(un, ui, dn, ll, email, id, role, crole, pid, pidt, created, null,
				new NullPointerException("disabledState"));
		failBuild(UserName.ROOT, ui, dn, created, email, id, Role.ROOT, crole, pid, pidt, ll, ds,
				new IllegalStateException("Root user cannot have identities"));
		failBuild(un, ui, dn, created, email, id, Role.ROOT, crole, pid, pidt, ll, ds,
				new IllegalStateException("Non-root username with root role"));
	}
	
	@Test
	public void failRootBuildRoles() throws Exception {
		final AuthUser.Builder b = AuthUser.getBuilder(
				UserName.ROOT, UID, new DisplayName("foo"), NOW);
		for (final Role r: Arrays.asList(
				Role.DEV_TOKEN, Role.SERV_TOKEN, Role.ADMIN, Role.CREATE_ADMIN)) {
			try {
				b.withRole(r);
				fail("expected exception");
			} catch (Exception got) {
				TestCommon.assertExceptionCorrect(got,
						new IllegalStateException("Root username must only have the ROOT role"));
			}
		}
	}
	
	private void failBuild(
			final UserName userName,
			final UUID anonymousID,
			final DisplayName displayName,
			final Instant created,
			final EmailAddress email,
			final RemoteIdentity identity,
			final Role role,
			final String customRole,
			final PolicyID policyID,
			final Instant policyTime,
			final Instant lastLogin,
			final UserDisabledState disabledState,
			final Exception e) {
		try {
			AuthUser.getBuilder(userName, anonymousID, displayName, created)
					.withEmailAddress(email)
					.withIdentity(identity)
					.withRole(role)
					.withCustomRole(customRole)
					.withPolicyID(policyID, policyTime)
					.withLastLogin(lastLogin)
					.withUserDisabledState(disabledState).build();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void immutableIdentities() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withIdentity(REMOTE).build();
		
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar2"),
				new RemoteIdentityDetails("user2", "full2", "email2"));
		
		try {
			u.getIdentities().add(ri);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
	@Test
	public void immutableRoles() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withRole(Role.DEV_TOKEN).build();
		
		try {
			u.getRoles().add(Role.ADMIN);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
	@Test
	public void immutableCustomRoles() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withCustomRole("foo").build();
		
		try {
			u.getCustomRoles().add("bar");
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
	@Test
	public void immutableGrantableRoles() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withRole(Role.ADMIN).build();
		
		try {
			u.getGrantableRoles().add(Role.ADMIN);
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
	@Test
	public void immutablePolicyIDs() throws Exception {
		final AuthUser u = AuthUser.getBuilder(
				new UserName("whoo"), UID, new DisplayName("bar3"), NOW)
				.withPolicyID(new PolicyID("foo"), Instant.now()).build();
		
		try {
			u.getPolicyIDs().put(new PolicyID("bar"), Instant.now());
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passed
		}
	}
	
	@Test
	public void sortedCustomRoles() throws Exception {
		final AuthUser u = AuthUser.getBuilder(new UserName("f"), UID, new DisplayName("u"),
				Instant.ofEpochMilli(10000))
				.withCustomRole("zoo")
				.withCustomRole("foo")
				.withCustomRole("goo")
				.withCustomRole("moo")
				.build();
		
		assertThat("custom roles not sorted", new LinkedList<>(u.getCustomRoles()),
				is(Arrays.asList("foo", "goo", "moo", "zoo")));
	}
	
	@Test
	public void sortedRoles() throws Exception {
		final AuthUser u = AuthUser.getBuilder(new UserName("f"), UID, new DisplayName("u"),
				Instant.ofEpochMilli(10000))
				.withRole(Role.SERV_TOKEN)
				.withRole(Role.ADMIN)
				.withRole(Role.CREATE_ADMIN)
				.withRole(Role.DEV_TOKEN)
				.build();
		
		assertThat("roles not sorted", new LinkedList<>(u.getRoles()),
				is(Arrays.asList(Role.ADMIN, Role.CREATE_ADMIN, Role.DEV_TOKEN, Role.SERV_TOKEN)));
	}
	
	@Test
	public void sortedPolicyIDs() throws Exception {
		final AuthUser u = AuthUser.getBuilder(new UserName("f"), UID, new DisplayName("u"),
				Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("zoo"), Instant.ofEpochMilli(10000))
				.withPolicyID(new PolicyID("mid2"), Instant.ofEpochMilli(15000))
				.withPolicyID(new PolicyID("aard"), Instant.ofEpochMilli(20000))
				.withPolicyID(new PolicyID("mid"), Instant.ofEpochMilli(30000))
				.build();
		
		assertThat("policy ids not sorted", new LinkedList<>(u.getPolicyIDs().keySet()),
				is(Arrays.asList(new PolicyID("aard"), new PolicyID("mid"), new PolicyID("mid2"),
						new PolicyID("zoo"))));
		
				
	}
}

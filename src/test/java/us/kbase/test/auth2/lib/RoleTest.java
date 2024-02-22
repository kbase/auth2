package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import us.kbase.auth2.lib.Role;

public class RoleTest {
	
	@Test
	public void getters() throws Exception {
		assertThat("incorrect id", Role.ROOT.getID(), is("Root"));
		assertThat("incorrect desc", Role.ROOT.getDescription(), is("Root"));
		
		assertThat("incorrect id", Role.CREATE_ADMIN.getID(), is("CreateAdmin"));
		assertThat("incorrect desc", Role.CREATE_ADMIN.getDescription(),
				is("Create administrator"));
		
		assertThat("incorrect id", Role.ADMIN.getID(), is("Admin"));
		assertThat("incorrect desc", Role.ADMIN.getDescription(), is("Administrator"));
		
		assertThat("incorrect id", Role.SERV_TOKEN.getID(), is("ServToken"));
		assertThat("incorrect desc", Role.SERV_TOKEN.getDescription(),
				is("Create server tokens"));
		
		assertThat("incorrect id", Role.DEV_TOKEN.getID(), is("DevToken"));
		assertThat("incorrect desc", Role.DEV_TOKEN.getDescription(),
				is("Create developer tokens"));
	}
	
	@Test
	public void getRole() throws Exception {
		try {
			Role.getRole("foo");
			fail("got bad role");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(), is("Invalid role id: foo"));
		}
		assertThat("incorrect role", Role.getRole("Root"), is(Role.ROOT));
		assertThat("incorrect role", Role.getRole("CreateAdmin"), is(Role.CREATE_ADMIN));
		assertThat("incorrect role", Role.getRole("Admin"), is(Role.ADMIN));
		assertThat("incorrect role", Role.getRole("ServToken"), is(Role.SERV_TOKEN));
		assertThat("incorrect role", Role.getRole("DevToken"), is(Role.DEV_TOKEN));
	}
	
	@Test
	public void isRole() throws Exception {
		assertThat("incorrect isRole()", Role.isRole(null), is(false));
		assertThat("incorrect isRole()", Role.isRole(""), is(false));
		assertThat("incorrect isRole()", Role.isRole("foo"), is(false));
		assertThat("incorrect role", Role.isRole("Root"), is(true));
		assertThat("incorrect role", Role.isRole("CreateAdmin"), is(true));
		assertThat("incorrect role", Role.isRole("Admin"), is(true));
		assertThat("incorrect role", Role.isRole("ServToken"), is(true));
		assertThat("incorrect role", Role.isRole("DevToken"), is(true));
	}
	
	private Set<Role> set(Role...roles) {
		return Arrays.stream(roles).collect(Collectors.toSet());
	}
	
	@Test
	public void included() throws Exception {
		assertThat("incorrect included()", Role.ROOT.included(), is(set(Role.ROOT)));
		assertThat("incorrect included()", Role.CREATE_ADMIN.included(),
				is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect included()", Role.ADMIN.included(),
				is(set(Role.ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect included()", Role.SERV_TOKEN.included(),
				is(set(Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect included()", Role.DEV_TOKEN.included(), is(set(Role.DEV_TOKEN)));
	}
	
	@Test
	public void canGrant() throws Exception {
		assertThat("incorrect canGrant()", Role.ROOT.canGrant(), is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect canGrant()", Role.CREATE_ADMIN.canGrant(),
				is(set(Role.ADMIN)));
		assertThat("incorrect canGrant()", Role.ADMIN.canGrant(),
				is(set(Role.SERV_TOKEN, Role.DEV_TOKEN)));
		assertThat("incorrect canGrant()", Role.SERV_TOKEN.canGrant(),
				is(Collections.emptySet()));
		assertThat("incorrect canGrant()", Role.DEV_TOKEN.canGrant(), is(Collections.emptySet()));
	}
	
	@Test
	public void isAdmin() throws Exception {
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.ROOT)), is(true));
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.CREATE_ADMIN)), is(true));
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.ADMIN)), is(true));
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.SERV_TOKEN)), is(false));
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.DEV_TOKEN)), is(false));
		assertThat("incorrect isAdmin()", Role.isAdmin(Collections.emptySet()), is(false));
		assertThat("incorrect isAdmin()", Role.isAdmin(set(Role.SERV_TOKEN, Role.DEV_TOKEN)),
				is(false));
		assertThat("incorrect isAdmin()", Role.isAdmin(
				set(Role.CREATE_ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN)), is(true));
	}
	
	@Test
	public void isSatisfiedBy() throws Exception {
		assertThat("incorrect isSatisfiedBy()", Role.SERV_TOKEN.isSatisfiedBy(
				set(Role.ADMIN, Role.DEV_TOKEN)), is(true));
		assertThat("incorrect isSatisfiedBy()", Role.SERV_TOKEN.isSatisfiedBy(
				set(Role.CREATE_ADMIN, Role.ROOT)), is(false));
		assertThat("incorrect isSatisfiedBy()", Role.CREATE_ADMIN.isSatisfiedBy(
				set(Role.ADMIN, Role.ROOT)), is(false));
		assertThat("incorrect isSatisfiedBy()", Role.CREATE_ADMIN.isSatisfiedBy(
				set(Role.CREATE_ADMIN, Role.ROOT)), is(true));
		assertThat("incorrect isSatisfiedBy()", Role.DEV_TOKEN.isSatisfiedBy(
				set(Role.SERV_TOKEN)), is(true));
	}

}

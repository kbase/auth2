package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** A user role. Grant privileges within the Authentication instance.
 * @author gaprice@lbl.gov
 *
 */
public enum Role {
	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	/** The root user. */
	ROOT			("Root", "Root"),
	/** User can create administrators. */
	CREATE_ADMIN	("CreateAdmin", "Create administrator"),
	/** User has administration privileges. */
	ADMIN			("Admin", "Administrator"),
	/** User can create server tokens. */
	SERV_TOKEN		("ServToken", "Create server tokens"),
	/** User can create developer tokens. */
	DEV_TOKEN		("DevToken", "Create developer tokens");
	
	private static final Map<String, Role> ROLE_MAP = new HashMap<>();
	static {
		for (final Role r: Role.values()) {
			ROLE_MAP.put(r.getID(), r);
		}
	}
	
	private final String id;
	private final String description;
	
	private Role(final String id, final String description) {
		this.id = id;
		this.description = description;
	}
	
	/** Get the id of the role.
	 * @return the role id.
	 */
	public String getID() {
		return id;
	}
	
	/** Get the description of the role.
	 * @return the role description.
	 */
	public String getDescription() {
		return description;
	}
	
	/** Get a role from the role ID.
	 * @param id the role ID.
	 * @return the role corresponding to the ID.
	 */
	public static Role getRole(final String id) {
		if (!ROLE_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid role id: " + id);
		}
		return ROLE_MAP.get(id);
	}
	
	/** Lists the roles that are included in this role.
	 * @return the included roles.
	 */
	public Set<Role> included() {
		if (Role.ADMIN.equals(this)) {
			return set(Role.ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		if (Role.SERV_TOKEN.equals(this)) {
			return set(Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		return set(this);
	}
	
	private Set<Role> set(Role...roles) {
		return Arrays.stream(roles).collect(Collectors.toSet());
	}
	
	/** Lists the roles that can be granted to another user by a user with this role.
	 * @return the grantable roles.
	 */
	public Set<Role> canGrant() {
		if (Role.ROOT.equals(this)) {
			return set(Role.CREATE_ADMIN);
		}
		if (Role.CREATE_ADMIN.equals(this)) {
			return set(Role.ADMIN);
		}
		if (Role.ADMIN.equals(this)) {
			return set(Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		return Collections.emptySet();
	}
	
	/** Returns true if a set of roles contains one of the administrator roles (ROOT, CREATE_ADMIN,
	 * or ADMIN).
	 * @param possessed the set of roles to check.
	 * @return true if the set of roles contains and administrator role.
	 */
	public static boolean isAdmin(final Set<Role> possessed) {
		if (possessed.contains(Role.ADMIN) ||
				possessed.contains(Role.CREATE_ADMIN) ||
				possessed.contains(Role.ROOT)) {
			return true;
		}
		return false;
	}
	
	/** Returns true if this role is included in at least one of the roles in the provided set.
	 * @param possessed the set to check.
	 * @return true if this role is included in one of the roles in the set.
	 */
	public boolean isSatisfiedBy(final Set<Role> possessed) {
		final Set<Role> included = possessed.stream().flatMap(r -> r.included().stream())
				.collect(Collectors.toSet());
		return included.contains(this);
		
	}
}

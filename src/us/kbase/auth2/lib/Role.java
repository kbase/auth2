package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public enum Role {
	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	ROOT			("Root", "Root"),
	CREATE_ADMIN	("CreateAdmin", "Create administrator"),
	ADMIN			("Admin", "Administrator"),
	DEV_TOKEN		("DevToken", "Create developer tokens"),
	SERV_TOKEN		("ServToken", "Create server tokens");
	
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
	
	public String getID() {
		return id;
	}
	
	public String getDescription() {
		return description;
	}
	
	public static Role getRole(final String id) {
		if (!ROLE_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid role id: " + id);
		}
		return ROLE_MAP.get(id);
	}
	
	public List<Role> included() {
		if (Role.ADMIN.equals(this)) {
			return Arrays.asList(Role.ADMIN, Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		if (Role.SERV_TOKEN.equals(this)) {
			return Arrays.asList(Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		return Arrays.asList(this);
	}
	
	public List<Role> grants() {
		if (Role.ROOT.equals(this)) {
			return Arrays.asList(Role.CREATE_ADMIN);
		}
		if (Role.CREATE_ADMIN.equals(this)) {
			return Arrays.asList(Role.ADMIN);
		}
		if (Role.ADMIN.equals(this)) {
			return Arrays.asList(Role.SERV_TOKEN, Role.DEV_TOKEN);
		}
		return new LinkedList<>();
	}
	
	public boolean isSatisfiedBy(final Set<Role> possessed) {
		final Set<Role> granted = possessed.stream()
				.flatMap(r -> r.included().stream())
				.collect(Collectors.toSet());
		return granted.contains(this);
		
	}
}

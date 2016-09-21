package us.kbase.auth2.lib.token;

import java.util.HashMap;
import java.util.Map;

public enum TokenType {

	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	LOGIN				("Login", "Login"),
	EXTENDED_LIFETIME	("ExtLife", "Extended lifetime");
	
	private static final Map<String, TokenType> TYPE_MAP = new HashMap<>();
	static {
		for (final TokenType tt: TokenType.values()) {
			TYPE_MAP.put(tt.getID(), tt);
		}
	}
	
	private final String id;
	private final String description;
	
	private TokenType(final String id, final String description) {
		this.id = id;
		this.description = description;
	}
	
	public String getID() {
		return id;
	}
	
	public String getDescription() {
		return description;
	}
	
	public static TokenType getType(final String id) {
		if (!TYPE_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid role id: " + id);
		}
		return TYPE_MAP.get(id);
	}
}

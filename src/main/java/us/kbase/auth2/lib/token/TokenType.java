package us.kbase.auth2.lib.token;

import java.util.HashMap;
import java.util.Map;

/** An enumeration representing the type of a token.
 * 
 * @author gaprice@lbl.gov
 *
 */
public enum TokenType {

	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	/** A standard login token. */
	LOGIN				("Login", "Login"),
	/** An agent token. */
	AGENT				("Agent", "Agent"),
	/** A developer token. */
	DEV					("Dev", "Developer"),
	/** A service token. */
	SERV				("Serv", "Service");
	
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
	
	/** Get the ID of this token type.
	 * @return the ID.
	 */
	public String getID() {
		return id;
	}
	
	/** Get the description of this token type.
	 * @return the description.
	 */
	public String getDescription() {
		return description;
	}
	
	/** Get a token type based on a supplied ID.
	 * @param type the id of the token type as a string.
	 * @return a token type.
	 * @throws IllegalArgumentException if there is no token type matching the ID.
	 */
	public static TokenType getType(final String type) {
		if (!TYPE_MAP.containsKey(type)) {
			throw new IllegalArgumentException("Invalid token type: " + type);
		}
		return TYPE_MAP.get(type);
	}
}

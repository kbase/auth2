package us.kbase.auth2.lib.token;

import java.util.HashMap;
import java.util.Map;

/** An enumeration representing the type of the token, either a standard login token or an 
 * extended lifetime token.
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
	/** An extended lifetype token. */
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
	 * @param id the id.
	 * @return a token type.
	 * @throws IllegalArgumentException if there is no token type matching the ID.
	 */
	public static TokenType getType(final String id) {
		if (!TYPE_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid role id: " + id);
		}
		return TYPE_MAP.get(id);
	}
}

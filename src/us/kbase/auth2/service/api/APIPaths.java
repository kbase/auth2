package us.kbase.auth2.service.api;

/** Resource paths in the API.
 * @author gaprice@lbl.gov
 *
 */
public class APIPaths {

	private static final String SEP = "/";
	private static final String TOKEN = "token";
	private static final String USERS = "users";
	/** The parameter name for a user name prefix. */
	public static final String PREFIX = "prefix";
	private static final String PREFIX_PARAM = "{" + PREFIX + "}";
	
	private static final String API = "/api";
	private static final String API_V2 = API + "/V2";
	private static final String API_LEGACY = API + "/legacy";
	
	/** The KBase legacy endpoint location. */
	public static final String LEGACY_KBASE = API_LEGACY + "/KBase/Sessions/Login";
	
	/** The root location of the Globus legacy endpoints. */
	public static final String LEGACY_GLOBUS = API_LEGACY + "/globus";
	
	/** The Globus token legacy endpoint location relative to the Globus root. */
	public static final String LEGACY_GLOBUS_USERS = USERS + SEP + "{user}";
	/** The Globus user legacy endpoint location relative to the Globus root. */
	public static final String LEGACY_GLOBUS_TOKEN = "goauth" + SEP + TOKEN;
	
	/** The token introspection endpoint location. */
	public static final String API_V2_TOKEN = API_V2 + SEP + TOKEN;
	
	/** The user lookup endpoint location. */
	public static final String API_V2_USERS = API_V2 + SEP + USERS;
	/** The user search endpoint location relative to the user lookup root. */
	public static final String USERS_SEARCH = "search" + SEP + PREFIX_PARAM;
	
	/** The me endpoint location. */
	public static final String API_V2_ME = API_V2 + SEP + "me";
}

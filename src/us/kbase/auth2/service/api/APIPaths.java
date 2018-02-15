package us.kbase.auth2.service.api;

/** Resource paths in the API.
 * @author gaprice@lbl.gov
 *
 */
public class APIPaths {

	private static final String SEP = "/";

	private static final String ME = "me";
	private static final String TOKEN = "token";
	private static final String USERS = "users";
	private static final String USER = "user";
	
	/** The parameter name for a user name prefix. */
	public static final String PREFIX = "prefix";
	
	/** The parameter name for a user name. */
	public static final String USERNAME = "username";
	
	private static final String PREFIX_PARAM = "{" + PREFIX + "}";
	private static final String LEGACY = "legacy";
	
	private static final String API = "/api";
	private static final String API_V2 = API + "/V2";
	private static final String API_LEGACY = API + SEP + LEGACY;
	
	/** The KBase legacy endpoint location. */
	public static final String LEGACY_KBASE = API_LEGACY + "/KBase/Sessions/Login";
	
	/** The root location of the Globus legacy endpoints. */
	public static final String LEGACY_GLOBUS = API_LEGACY + SEP + "globus";
	
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
	public static final String API_V2_ME = API_V2 + SEP + ME;
	
	/* test mode endpoints. */

	/** The testmode root endpoint. */
	public static final String TESTMODE = "/testmode";
	
	private static final String TESTMODE_ONLY = "testmodeonly";
	
	/** The testmode token introspection endpoint. */
	public static final String TESTMODE_TOKEN = API_V2_TOKEN;
	
	/** The testmode test token creation endpoint. */
	public static final String TESTMODE_TOKEN_CREATE = API_V2 + SEP + TESTMODE_ONLY + SEP + TOKEN;
	
	/** The test mode user creation endpoint. */
	public static final String TESTMODE_USER = API_V2 + SEP + TESTMODE_ONLY + SEP + USER;
	
	/** The test mode user retrieval endpoint. */
	public static final String TESTMODE_USER_GET = TESTMODE_USER + SEP + "{" + USERNAME + "}";
	
	/** The test mode user display name endpoint. */
	public static final String TESTMODE_USER_DISPLAY = API_V2_USERS;
	
	/** The test mode me endpoint. */
	public static final String TESTMODE_ME = API_V2_ME;
	
	/** The test mode custom roles endpoint. */
	public static final String TESTMODE_CUSTOM_ROLES = API_V2 + SEP + TESTMODE_ONLY + SEP +
			"customroles";
	
	/** The test mode user roles endpoint. */
	public static final String TESTMODE_USER_ROLES = API_V2 + SEP + TESTMODE_ONLY + SEP +
			"userroles";
	
	/** The test mode clear endpoint. */
	public static final String TESTMODE_CLEAR = API_V2 + SEP + TESTMODE_ONLY + SEP + "clear";
	
	/** The test mode globus token endpoint. */
	public static final String TESTMODE_GLOBUS_TOKEN = LEGACY_GLOBUS + SEP + LEGACY_GLOBUS_TOKEN;
	
	/** The test mode globus user endpoint. */
	public static final String TESTMODE_GLOBUS_USER = LEGACY_GLOBUS + SEP + LEGACY_GLOBUS_USERS;
	
	/** The test mode KBase token endpoint. */
	public static final String TESTMODE_KBASE_TOKEN = LEGACY_KBASE;
}

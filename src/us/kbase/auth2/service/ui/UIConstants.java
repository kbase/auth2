package us.kbase.auth2.service.ui;

import us.kbase.auth2.service.api.APIConstants;

public class UIConstants {

	// this is mostly here so locations are easy to find if some other
	// strategy needs to be implemented
	/** Whether to only allow sending cookies over https */
	public static final boolean SECURE_COOKIES = false;
	
	/** The header key for an authorization token. */
	public static final String HEADER_TOKEN = APIConstants.HEADER_TOKEN;
	
	/** The number of seconds before OAuth2 cookies set when redirecting a user to the OAuth2
	 * provider expire, ending the OAuth2 session.
	 */
	public static final int PROVIDER_RETURN_EXPIRATION_SEC = 30 * 60;
}

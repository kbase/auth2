package us.kbase.auth2.lib.exceptions;

import java.util.HashMap;
import java.util.Map;

/** An enum representing the type of a particular error.
 * @author gaprice@lbl.gov
 *
 */
public enum ErrorType {
	
	// be very careful about changing error type ids as they are stored in the DB with
	// temporary tokens
	
	/** Lack of a required identity or other error. */
	AUTHENTICATION_FAILED	(10000, "Authentication failed"),
	/** No token was provided when required */
	NO_TOKEN				(10010, "No authentication token"),
	/** The token provided is not valid. */
	INVALID_TOKEN			(10020, "Invalid token"),
	/** Retrieving identities from a 3rd party provider failed. */
	ID_RETRIEVAL_FAILED		(10030, "Identity retrieval failed"),
	/** A 3rd party identity provider reported an error at the conclusion of the OAuth2 flow. */
	ID_PROVIDER_ERROR		(10040, "Identity provider error"),
	/** The password and username did not match. */
	PASSWORD_MISMATCH		(10050, "Password / username mismatch"),
	/** The user is not authorized to perform the requested action. */
	UNAUTHORIZED			(20000, "Unauthorized"),
	/** The account to be accessed is disabled. */
	DISABLED				(20010, "Account disabled"),
	/** A required input parameter was not provided. */
	MISSING_PARAMETER		(30000, "Missing input parameter"),
	/** An input parameter had an illegal value. */
	ILLEGAL_PARAMETER		(30001, "Illegal input parameter"),
	/** The provided user name was not legal. */
	ILLEGAL_USER_NAME		(30010, "Illegal user name"),
	/** The provided email address was not legal. */
	ILLEGAL_EMAIL_ADDRESS	(30020, "Illegal email address"),
	/** The provided password was not legal. */
	ILLEGAL_PASSWORD		(30030, "Illegal password"),
	/** The user could not be created because it already exists. */
	USER_ALREADY_EXISTS		(40000, "User already exists"),
	/** The identity is already linked to a different user */
	ID_ALREADY_LINKED		(40010, "Identity already linked"),
	/** The requested user does not exist. */
	NO_SUCH_USER			(50000, "No such user"),
	/** The requested local user does not exist. */
	NO_SUCH_LOCAL_USER		(50001, "No such local user"),
	/** The requested token does not exist. */
	NO_SUCH_TOKEN			(50010, "No such token"),
	/** The requested identity provider does not exist. */
	NO_SUCH_IDENT_PROV		(50020, "No such identity provider"),
	/** The requested identity does not exist. */
	NO_SUCH_IDENTITY		(50030, "No such identity"),
	/** The requested role does not exist. */
	NO_SUCH_ROLE			(50040, "No such role"),
	/** The requested environment does not exist. */
	NO_SUCH_ENVIRONMENT		(50040, "No such environment"),
	/** The attempt to link one account to another failed. */
	LINK_FAILED				(60000, "Account linkage failed"),
	/** The attempt to unlink one account from another failed. */
	UNLINK_FAILED			(60010, "Account unlink failed"),
	/** The requested operation is not supported. */
	UNSUPPORTED_OP			(70000, "Unsupported operation");
	
	private static final Map<Integer, ErrorType> ERROR_MAP = new HashMap<>();
	static {
		for (final ErrorType t: ErrorType.values()) {
			ERROR_MAP.put(t.getErrorCode(), t);
		}
	}
	
	/** Get an ErrorType given the error code.
	 * @param code the error code.
	 * @return the ErrorType corresponding to the error code.
	 */
	public static ErrorType fromErrorCode(final int code) {
		if (!ERROR_MAP.containsKey(code)) {
			throw new IllegalArgumentException("Invalid error code: " + code);
		}
		return ERROR_MAP.get(code);
	}
	
	private final int errcode;
	private final String error;
	
	private ErrorType(final int errcode, final String error) {
		this.errcode = errcode;
		this.error = error;
	}

	/** Get the error code for the error type.
	 * @return the error code.
	 */
	public int getErrorCode() {
		return errcode;
	}

	/** Get a text description of the error type.
	 * @return the error.
	 */
	public String getError() {
		return error;
	}

}

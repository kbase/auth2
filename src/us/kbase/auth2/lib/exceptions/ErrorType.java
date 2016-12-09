package us.kbase.auth2.lib.exceptions;

public enum ErrorType {
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	AUTHENTICATION_FAILED	(10000, "Authentication failed"),
	NO_TOKEN				(10010, "No authentication token"),
	INVALID_TOKEN			(10011, "Invalid token"),
	ID_RETRIEVAL_FAILED		(10020, "Identity retrieval failed"),
	UNAUTHORIZED			(20000, "Unauthorized"),
	DISABLED				(20010, "Account disabled"),
	MISSING_PARAMETER		(30000, "Missing input parameter"),
	ILLEGAL_PARAMETER		(30001, "Illegal input parameter"),
	ILLEGAL_USER_NAME		(30010, "Illegal user name"),
	USER_ALREADY_EXISTS		(40000, "User already exists"),
	NO_SUCH_USER			(50000, "No such user"),
	NO_SUCH_LOCAL_USER		(50001, "No such local user"),
	NO_SUCH_TOKEN			(50010, "No such token"),
	NO_SUCH_IDENT_PROV		(50020, "No such identity provider"),
	NO_SUCH_ROLE			(50030, "No such role"),
	LINK_FAILED				(60000, "Account linkage failed"),
	UNLINK_FAILED			(60010, "Account unlink failed"),
	UNSUPPORTED_OP			(70000, "Unsupported operation");
	
	private final int errcode;
	private final String error;
	
	ErrorType(final int errcode, final String error) {
		this.errcode = errcode;
		this.error = error;
	}

	public int getErrorCode() {
		return errcode;
	}

	public String getError() {
		return error;
	}

}

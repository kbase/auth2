package us.kbase.auth2.lib.exceptions;

public enum ErrorType {
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	AUTHENTICATION_FAILED	(10000, "Authentication failed"),
	NO_TOKEN				(10001, "No authentication token"),
	INVALID_TOKEN			(10002, "Invalid token"),
	ID_RETRIEVAL_FAILED		(10003, "Identity retrieval failed"),
	UNAUTHORIZED			(20000, "Unauthorized"),
	DISABLED				(20001, "Account disabled"),
	MISSING_PARAMETER		(30000, "Missing input parameter"),
	ILLEGAL_PARAMETER		(30001, "Illegal input parameter"),
	ILLEGAL_USER_NAME		(30002, "Illegal user name"),
	USER_ALREADY_EXISTS		(40000, "User already exists"),
	NO_SUCH_USER			(50000, "No such user"),
	NO_SUCH_TOKEN			(50001, "No such token"),
	NO_SUCH_IDENT_PROV		(50002, "No such identity provider"),
	NO_SUCH_ROLE			(50003, "No such role"),
	LINK_FAILED				(60000, "Account linkage failed"),
	UNLINK_FAILED			(60001, "Account unlink failed"),
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

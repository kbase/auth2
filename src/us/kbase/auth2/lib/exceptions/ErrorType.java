package us.kbase.auth2.lib.exceptions;

public enum ErrorType {
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	AUTHENTICATION_FAILED	(10000, "Authentication failed"),
	NO_TOKEN				(10001, "No authentication token"),
	INVALID_TOKEN			(10002, "Invalid token"),
	ID_RETRIEVAL_FAILED		(10003, "Identity retrieval failed"),
	UNAUTHORIZED			(20000, "Unauthorized"),
	MISSING_PARAMETER		(30000, "Missing input parameter"),
	ILLEGAL_PARAMETER		(30001, "Illegal input parameter"),
	USER_ALREADY_EXISTS		(30002, "User already exists"),
	NO_SUCH_USER			(30003, "No such user"),
	NO_SUCH_TOKEN			(30004, "No such token"),
	NO_SUCH_IDENT_PROV		(30005, "No such identity provider"),
	NO_SUCH_ROLE			(30005, "No such role"),
	LINK_FAILED				(40000, "Account linkage failed"),
	UNLINK_FAILED			(40001, "Account unlink failed"),
	UNSUPPORTED_OP			(50000, "Unsupported opertation");
	
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

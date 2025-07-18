package us.kbase.auth2.lib.identity;

/** An enumeration representing the multi-factor authentication status of a user's login. */
public enum MfaStatus {
	/** User authenticated with MFA during token creation. */
	USED,
	/** User explicitly chose not to use MFA when available. */
	NOT_USED,
	/** MFA status unknown or not applicable to authentication method. */
	UNKNOWN;
}
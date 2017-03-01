package us.kbase.auth2.service.common;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.service.common.IncomingJSON;

public class IdentityProviderInput extends IncomingJSON {
	
	//TODO JAVADOC
	//TODO TESTS
	
	private final String authCode;
	private final String state;

	@JsonCreator
	public IdentityProviderInput(
			@JsonProperty("authcode") final String authCode,
			@JsonProperty("state") final String state) {
		this.authCode = authCode;
		this.state = state;
	}

	public String getAuthCode() {
		return authCode;
	}

	public String getState() {
		return state;
	}
	
	public void checkState(final String cookieSessionState)
			throws MissingParameterException, AuthenticationException {
		checkState(cookieSessionState, state);
	}
	
	public static void checkState(
			final String cookieSessionState,
			final String providerSuppliedState)
			throws MissingParameterException, AuthenticationException {
		if (cookieSessionState == null || cookieSessionState.trim().isEmpty()) {
			throw new MissingParameterException("Couldn't retrieve state value from cookie");
		}
		if (!cookieSessionState.equals(providerSuppliedState)) {
			throw new AuthenticationException(ErrorType.AUTHENTICATION_FAILED,
					"State values do not match, this may be a CXRF attack");
		}
	}
}
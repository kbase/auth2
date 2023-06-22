package us.kbase.auth2.service.exceptions;

import static java.util.Objects.requireNonNull;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.JsonMappingException;

import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.NoDataException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;

@JsonInclude(Include.NON_NULL)
public class ErrorMessage {
	
	//TODO TEST unit tests
	//TODO JAVADOC

	private final int httpcode;
	private final String httpstatus;
	private final Integer appcode;
	private final String apperror;
	private final String message;
	private final String exception;
	private final String callid;
	private final long time = Instant.now().toEpochMilli();
	@JsonIgnore
	private final List<String> exceptionlines;
	@JsonIgnore
	private final boolean hasexception;
	
	public ErrorMessage(
			final Throwable ex,
			final String callID,
			final boolean includeTrace) {
		requireNonNull(ex, "ex");
		this.callid = callID; // null ok
		if (includeTrace) {
			final StringWriter st = new StringWriter();
			ex.printStackTrace(new PrintWriter(st));
			exception = st.toString();
			exceptionlines = Collections.unmodifiableList(
					Arrays.asList(exception.split("\n")));
			hasexception = true;
		} else {
			exception = null;
			exceptionlines = null;
			hasexception = false;
		}
		message = ex.getMessage();
		final StatusType status;
		if (ex instanceof AuthException) {
			final AuthException ae = (AuthException) ex;
			appcode = ae.getErr().getErrorCode();
			apperror = ae.getErr().getError();
			if (ae instanceof AuthenticationException) {
				status = Response.Status.UNAUTHORIZED;
			} else if (ae instanceof UnauthorizedException) {
				status = Response.Status.FORBIDDEN;
			} else if (ae instanceof NoDataException) {
				status = Response.Status.NOT_FOUND;
			} else {
				status = Response.Status.BAD_REQUEST;
			}
		} else if (ex instanceof WebApplicationException) {
			appcode = null;
			apperror = null;
			status = ((WebApplicationException) ex).getResponse()
					.getStatusInfo();
		} else if (ex instanceof JsonMappingException) {
			/* we assume that any json exceptions are because the client sent bad JSON data.
			 * This may not 100% accurate, but if we're attempting to return unserializable data
			 * that should be caught in tests.
			 */
			appcode = null;
			apperror = null;
			status = Response.Status.BAD_REQUEST;
		} else {
			appcode = null;
			apperror = null;
			status = Response.Status.INTERNAL_SERVER_ERROR;
		}
		httpcode = status.getStatusCode();
		httpstatus = status.getReasonPhrase();
	}

	public int getHttpcode() {
		return httpcode;
	}

	public String getHttpstatus() {
		return httpstatus;
	}

	public Integer getAppcode() {
		return appcode;
	}

	public String getApperror() {
		return apperror;
	}

	public String getMessage() {
		return message;
	}

	public String getException() {
		return exception;
	}

	public List<String> getExceptionlines() {
		return exceptionlines;
	}

	public boolean hasexception() {
		return hasexception;
	}

	public String getCallid() {
		return callid;
	}

	public long getTime() {
		return time;
	}
}

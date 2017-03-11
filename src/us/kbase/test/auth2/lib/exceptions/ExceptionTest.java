package us.kbase.test.auth2.lib.exceptions;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.AuthenticationException;
import us.kbase.auth2.lib.exceptions.DisabledUserException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoDataException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;

public class ExceptionTest {
	
	/* This only tests exceptions using the ErrorType class. Standard exceptions are so simple
	 * they're not worth testing (usually just 1-2 constructors that call super()).
	 */
	
	@Test
	public void errorType() throws Exception {
		// only going to test one of these to handle the additions, no need to retest enum
		// mechanics
		final ErrorType et = ErrorType.DISABLED;
		assertThat("incorrect error id", et.getErrorCode(), is(20010));
		assertThat("incorrect error", et.getError(), is("Account disabled"));
	}
	
	@Test
	public void authentication() throws Exception {
		final ErrorType et = ErrorType.AUTHENTICATION_FAILED;
		final AuthenticationException ae = new AuthenticationException(et, "foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final ErrorType et2 = ErrorType.DISABLED;
		final AuthenticationException ae2 = new AuthenticationException(et2, "foo2",
				new NullPointerException());
		assertThat("incorrect error code", ae2.getErr(), is(et2));
		assertThat("incorrect message", ae2.getMessage(), is(format(et2, "foo2")));
		assertThat("incorrect cause", ae2.getCause(), instanceOf(NullPointerException.class));
	}

	private String format(final ErrorType et, final String msg) {
		if (msg == null) {
			return String.format("%s %s", et.getErrorCode(), et.getError());
		}
		return String.format("%s %s: %s", et.getErrorCode(), et.getError(), msg);
	}
	
	@Test
	public void authException() throws Exception {
		final ErrorType et = ErrorType.ID_RETRIEVAL_FAILED;
		final AuthException ae = new AuthException(et, "foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final ErrorType et2 = ErrorType.ILLEGAL_PARAMETER;
		final AuthException ae2 = new AuthException(et2, null, new NullPointerException());
		assertThat("incorrect error code", ae2.getErr(), is(et2));
		assertThat("incorrect message", ae2.getMessage(), is(format(et2, null)));
		assertThat("incorrect cause", ae2.getCause(), instanceOf(NullPointerException.class));
		
		final AuthException ae3 = new AuthException(et2, "\t");
		assertThat("incorrect error code", ae3.getErr(), is(et2));
		assertThat("incorrect message", ae3.getMessage(), is(format(et2, null)));
		assertThat("incorrect cause", ae3.getCause(), is((Throwable) null));
		
		try {
			new AuthException(null, null);
			fail("created bad exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("err"));
		}
	}
	
	@Test
	public void disabledUser() throws Exception {
		final ErrorType et = ErrorType.DISABLED;
		final DisabledUserException ae = new DisabledUserException();
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, null)));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final DisabledUserException ae2 = new DisabledUserException("foo");
		assertThat("incorrect error code", ae2.getErr(), is(et));
		assertThat("incorrect message", ae2.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae2.getCause(), is((Throwable) null));
	}
	
	@Test
	public void identityRetrieval() throws Exception {
		final ErrorType et = ErrorType.ID_RETRIEVAL_FAILED;
		final IdentityRetrievalException ae = new IdentityRetrievalException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final IllegalArgumentException ie = new IllegalArgumentException("bar");
		final IdentityRetrievalException ae2 = new IdentityRetrievalException("baz", ie);
		assertThat("incorrect error code", ae2.getErr(), is(et));
		assertThat("incorrect message", ae2.getMessage(), is(format(et, "baz")));
		assertThat("incorrect cause", ae2.getCause(), is(ie));
	}
	
	@Test
	public void identityLinked() throws Exception {
		final ErrorType et = ErrorType.ID_ALREADY_LINKED;
		final IdentityLinkedException ile = new IdentityLinkedException("bar");
		assertThat("incorrect error code", ile.getErr(), is(et));
		assertThat("incorrect message", ile.getMessage(), is(format(et, "bar")));
		assertThat("incorrect cause", ile.getCause(), is((Throwable) null));
	}
	
	@Test
	public void illegalPassword() throws Exception {
		final ErrorType et = ErrorType.ILLEGAL_PASSWORD;
		final IllegalPasswordException ipe = new IllegalPasswordException("foo");
		assertThat("incorrect error code", ipe.getErr(), is(et));
		assertThat("incorrect message", ipe.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ipe.getCause(), is((Throwable) null));
	}
	
	@Test
	public void illegalParameter() throws Exception {
		final ErrorType et = ErrorType.ILLEGAL_PARAMETER;
		final IllegalParameterException ae = new IllegalParameterException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final IllegalParameterException ae2 = new IllegalParameterException("foo2",
				new NullPointerException());
		assertThat("incorrect error code", ae2.getErr(), is(et));
		assertThat("incorrect message", ae2.getMessage(), is(format(et, "foo2")));
		assertThat("incorrect cause", ae2.getCause(), instanceOf(NullPointerException.class));
		
		final ErrorType et3 = ErrorType.NO_SUCH_USER;
		final IllegalParameterException ae3 = new IllegalParameterException(et3, "");
		assertThat("incorrect error code", ae3.getErr(), is(et3));
		assertThat("incorrect message", ae3.getMessage(), is(format(et3, null)));
		assertThat("incorrect cause", ae3.getCause(), is((Throwable) null));
	}
	
	@Test
	public void invalidToken() throws Exception {
		final ErrorType et = ErrorType.INVALID_TOKEN;
		final InvalidTokenException ae = new InvalidTokenException();
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, null)));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final InvalidTokenException ae2 = new InvalidTokenException("foo");
		assertThat("incorrect error code", ae2.getErr(), is(et));
		assertThat("incorrect message", ae2.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae2.getCause(), is((Throwable) null));
	}
	
	@Test
	public void linkFailed() throws Exception {
		final ErrorType et = ErrorType.LINK_FAILED;
		final LinkFailedException ae = new LinkFailedException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void missingParameter() throws Exception {
		final ErrorType et = ErrorType.MISSING_PARAMETER;
		final MissingParameterException ae = new MissingParameterException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noDataException() throws Exception {
		final ErrorType et = ErrorType.MISSING_PARAMETER;
		final NoDataException ae = new NoDataException(et, "foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchIdentity() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_IDENTITY;
		final NoSuchIdentityException ae = new NoSuchIdentityException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchIdentityProvider() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_IDENT_PROV;
		final NoSuchIdentityProviderException ae = new NoSuchIdentityProviderException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchLocalUser() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_LOCAL_USER;
		final NoSuchLocalUserException ae = new NoSuchLocalUserException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchRole() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_ROLE;
		final NoSuchRoleException ae = new NoSuchRoleException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchToken() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_TOKEN;
		final NoSuchTokenException ae = new NoSuchTokenException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noSuchUser() throws Exception {
		final ErrorType et = ErrorType.NO_SUCH_USER;
		final NoSuchUserException ae = new NoSuchUserException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void noTokenProvided() throws Exception {
		final ErrorType et = ErrorType.NO_TOKEN;
		final NoTokenProvidedException ae = new NoTokenProvidedException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void unauthorizedException() throws Exception {
		final ErrorType et = ErrorType.UNAUTHORIZED;
		final UnauthorizedException ae = new UnauthorizedException(et);
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, null)));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
		
		final ErrorType et2 = ErrorType.UNLINK_FAILED;
		final UnauthorizedException ae2 = new UnauthorizedException(et2, "foo");
		assertThat("incorrect error code", ae2.getErr(), is(et2));
		assertThat("incorrect message", ae2.getMessage(), is(format(et2, "foo")));
		assertThat("incorrect cause", ae2.getCause(), is((Throwable) null));
	}
	
	@Test
	public void unlinkFailed() throws Exception {
		final ErrorType et = ErrorType.UNLINK_FAILED;
		final UnLinkFailedException ae = new UnLinkFailedException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
	
	@Test
	public void userExists() throws Exception {
		final ErrorType et = ErrorType.USER_ALREADY_EXISTS;
		final UserExistsException ae = new UserExistsException("foo");
		assertThat("incorrect error code", ae.getErr(), is(et));
		assertThat("incorrect message", ae.getMessage(), is(format(et, "foo")));
		assertThat("incorrect cause", ae.getCause(), is((Throwable) null));
	}
}

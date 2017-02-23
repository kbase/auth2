package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import org.apache.commons.validator.routines.EmailValidator;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** An email address.
 * @author gaprice@lbl.gov
 *
 */
public class EmailAddress {

	private static final EmailValidator validator = EmailValidator.getInstance(false);
	
	/** An unknown email address. Always returns null for the address. */
	public final static EmailAddress UNKNOWN = new EmailAddress(); // maybe want a specific class rather than just returning null
	
	private final static int MAX_EMAIL_LENGTH = 1000;
	
	private final String email;
	
	private EmailAddress() {
		this.email = null;
	}
	
	/** Create an email address.
	 * @param email the email address.
	 * @throws MissingParameterException if the email address is null or the empty string.
	 * @throws IllegalParameterException if the email address is not valid or more than 1000
	 * characters.
	 */
	public EmailAddress(final String email)
			throws MissingParameterException, IllegalParameterException {
		checkString(email, "email address", MAX_EMAIL_LENGTH);
		if (!validator.isValid(email)) {
			throw new IllegalParameterException(ErrorType.ILLEGAL_EMAIL_ADDRESS, email);
		}
		this.email = email.trim();
	}

	/** Get the email address. Returns null if the email address is unknown.
	 * @return the email address.
	 */
	public String getAddress() {
		return email;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("EmailAddress [email=");
		builder.append(email);
		builder.append("]");
		return builder.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		EmailAddress other = (EmailAddress) obj;
		if (email == null) {
			if (other.email != null) {
				return false;
			}
		} else if (!email.equals(other.email)) {
			return false;
		}
		return true;
	}

	
}

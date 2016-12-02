package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class EmailAddress {

	//TODO TEST
	//TODO JAVADOC
	
	public final static EmailAddress UNKNOWN = new EmailAddress(); // maybe want a specific class rather than just returning null
	private final static int MAX_EMAIL_LENGTH = 1000;
	
	private final String email;
	
	private EmailAddress() {
		this.email = null;
	}
	
	public EmailAddress(final String email)
			throws MissingParameterException, IllegalParameterException {
		//TODO EMAIL do some validation here - ideally find a library. DO NOT actually validate by sending an email.
		checkString(email, "email address", MAX_EMAIL_LENGTH);
		this.email = email.trim();
	}

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

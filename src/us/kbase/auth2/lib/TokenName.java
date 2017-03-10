package us.kbase.auth2.lib;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class TokenName extends Name {
	
	public TokenName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name, "token name", 30);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("TokenName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}

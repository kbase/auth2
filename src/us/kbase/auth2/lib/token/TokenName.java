package us.kbase.auth2.lib.token;

import us.kbase.auth2.lib.Name;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class TokenName extends Name {
	
	public TokenName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name, "token name", 100);
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

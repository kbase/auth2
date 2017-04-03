package us.kbase.auth2.service;

import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.TokenCreationContext.Builder;

public class UserAgentParser {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final UserAgentAnalyzer uaa;
	
	public UserAgentParser() {
		// this is slooow. Only want to do it once per service start.
		uaa = UserAgentAnalyzer.newBuilder()
				.withField(UserAgent.DEVICE_NAME)
				.withField(UserAgent.OPERATING_SYSTEM_NAME)
				.withField(UserAgent.OPERATING_SYSTEM_VERSION)
				.withField(UserAgent.AGENT_NAME)
				.withField(UserAgent.AGENT_VERSION)
				.build();
	}
	
	public synchronized Builder getTokenContextFromUserAgent(final String userAgent) {
		//TODO LOG if any fields = Hacker log HackerAttackVector and HackerToolkit fields
		final UserAgent ua = uaa.parse(userAgent);
		return TokenCreationContext.getBuilder()
				.withNullableAgent(filter(ua.getValue(UserAgent.AGENT_NAME)),
						filter(ua.getValue(UserAgent.AGENT_VERSION)))
				.withNullableOS(filter(ua.getValue(UserAgent.OPERATING_SYSTEM_NAME)),
						filter(ua.getValue(UserAgent.OPERATING_SYSTEM_VERSION)))
				.withNullableDevice(filter(ua.getValue(UserAgent.DEVICE_NAME)));
	}
	
	private String filter(final String value) {
		// some values spit out by UAA are just ??, which is not helpful
		if (value.replace("\\s", "").replace("?", "").isEmpty()) {
			return null;
		}
		if ("Unknown".equals(value)) {
			return null;
		}
		return value;
	}

	public static void main(String[] args) {
		final UserAgentParser tcb = new UserAgentParser();
		tcb.getTokenContextFromUserAgent("here's some shit you can't parse mfer");
	}

}

package us.kbase.auth2.service.ui;

import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.service.common.ExternalToken;

public class UIToken extends ExternalToken {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final String os;
	private final String osver;
	private final String agent;
	private final String agentver;
	private final String device;
	private final String ip;

	public UIToken(final StoredToken st) {
		super(st);
		final TokenCreationContext ctx = st.getContext();
		os = ctx.getOS().isPresent() ? ctx.getOS().get() : null;
		osver = ctx.getOSVersion().isPresent() ? ctx.getOSVersion().get() : null;
		agent = ctx.getAgent().isPresent() ? ctx.getAgent().get() : null;
		agentver = ctx.getAgentVersion().isPresent() ? ctx.getAgentVersion().get() : null;
		device = ctx.getDevice().isPresent() ? ctx.getDevice().get() : null;
		ip = ctx.getIpAddress().isPresent() ? ctx.getIpAddress().get().toString() : null;
	}

	public String getOs() {
		return os;
	}

	public String getOsver() {
		return osver;
	}

	public String getAgent() {
		return agent;
	}

	public String getAgentver() {
		return agentver;
	}

	public String getDevice() {
		return device;
	}

	public String getIp() {
		return ip;
	}
}

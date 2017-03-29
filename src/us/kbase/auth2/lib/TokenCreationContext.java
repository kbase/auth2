package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class TokenCreationContext {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final Set<PolicyID> policyIDs;
	private final Optional<String> userAgent;
	private final Optional<InternetAddress> ipAddress;
	private final Map<String, String> customContext;
	
	private TokenCreationContext(
			final Set<PolicyID> policyIDs,
			final Optional<String> userAgent,
			final Optional<InternetAddress> ipAddress,
			final Map<String, String> customContext) {
		this.policyIDs = Collections.unmodifiableSet(policyIDs);
		this.userAgent = userAgent;
		this.ipAddress = ipAddress;
		this.customContext = Collections.unmodifiableMap(customContext);
	}

	public Set<PolicyID> getPolicyIDs() {
		return policyIDs;
	}

	public Optional<String> getUserAgent() {
		return userAgent;
	}

	public Optional<InternetAddress> getIpAddress() {
		return ipAddress;
	}
	
	public Map<String, String> getCustomContext() {
		return customContext;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((customContext == null) ? 0 : customContext.hashCode());
		result = prime * result + ((ipAddress == null) ? 0 : ipAddress.hashCode());
		result = prime * result + ((policyIDs == null) ? 0 : policyIDs.hashCode());
		result = prime * result + ((userAgent == null) ? 0 : userAgent.hashCode());
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
		TokenCreationContext other = (TokenCreationContext) obj;
		if (customContext == null) {
			if (other.customContext != null) {
				return false;
			}
		} else if (!customContext.equals(other.customContext)) {
			return false;
		}
		if (ipAddress == null) {
			if (other.ipAddress != null) {
				return false;
			}
		} else if (!ipAddress.equals(other.ipAddress)) {
			return false;
		}
		if (policyIDs == null) {
			if (other.policyIDs != null) {
				return false;
			}
		} else if (!policyIDs.equals(other.policyIDs)) {
			return false;
		}
		if (userAgent == null) {
			if (other.userAgent != null) {
				return false;
			}
		} else if (!userAgent.equals(other.userAgent)) {
			return false;
		}
		return true;
	}
	
	public static Builder getBuilder() {
		return new Builder();
	}
	
	public static class Builder {
		
		private static final int MAX_CUSTOM_CONTEXT_MAP_ENTRIES = 100;
		private static final int MAX_CUSTOM_CONTEXT_VALUE_LENGTH = 80;
		private static final int MAX_CUSTOM_CONTEXT_KEY_LENGTH = 20;
		private static final int USER_AGENT_TRUNCATED_AFTER = 1000;
		private final Set<PolicyID> policyIDs = new HashSet<>();
		private Optional<String> userAgent = Optional.absent();
		private Optional<InternetAddress> ipAddress = Optional.absent();
		private Map<String, String> customContext = new HashMap<>();
		
		private Builder() {};
		
		public Builder withPolicyID(final PolicyID policyID) {
			nonNull(policyID, "policyID");
			policyIDs.add(policyID);
			return this;
		}
		
		public Builder withUserAgent(String userAgent) throws MissingParameterException {
			//TODO NOW don't keep entire user agent. Use a parser to keep interesting fields. Make this class know nothing about the user agent. https://github.com/nielsbasjes/yauaa
			checkString(userAgent, "userAgent");
			if (userAgent.length() > USER_AGENT_TRUNCATED_AFTER) {
				userAgent = userAgent.substring(0, USER_AGENT_TRUNCATED_AFTER);
			}
			this.userAgent = Optional.of(userAgent);
			return this;
		}
		
		public Builder withIpAddress(final InternetAddress ipAddress) {
			nonNull(ipAddress, "ipAddress");
			this.ipAddress = Optional.of(ipAddress);
			return this;
		}
		
		public Builder withCustomContext(final String key, final String value)
				throws MissingParameterException, IllegalParameterException {
			checkString(key, "key", MAX_CUSTOM_CONTEXT_KEY_LENGTH);
			checkString(value, "value", MAX_CUSTOM_CONTEXT_VALUE_LENGTH);
			this.customContext.put(key, value);
			if (customContext.size() > MAX_CUSTOM_CONTEXT_MAP_ENTRIES) {
				throw new IllegalParameterException(
						"Exceeded max size of custom context: " + MAX_CUSTOM_CONTEXT_MAP_ENTRIES + 
						" items");
			}
			return this;
		}
		
		public TokenCreationContext build() {
			return new TokenCreationContext(policyIDs, userAgent, ipAddress, customContext);
		}
	}
	
	

}

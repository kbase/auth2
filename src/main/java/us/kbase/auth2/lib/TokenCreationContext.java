package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.checkString;

import java.net.InetAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** Represents the context in which a user token was created - e.g. the user's operating system,
 * agent/web browser, device, IP address, and any custom context that might be supplied when
 * creating the token.
 * @author gaprice@lbl.gov
 *
 */
public class TokenCreationContext {
	
	private final Optional<String> os;
	private final Optional<String> osVersion;
	private final Optional<String> agent;
	private final Optional<String> agentVersion;
	private final Optional<String> device;
	private final Optional<InetAddress> ipAddress;
	private final Map<String, String> customContext;
	
	private TokenCreationContext(
			final Optional<String> os,
			final Optional<String> osVersion,
			final Optional<String> agent,
			final Optional<String> agentVersion,
			final Optional<String> device,
			final Optional<InetAddress> ipAddress,
			final Map<String, String> customContext) {
		this.os = os;
		this.osVersion = osVersion;
		this.agent = agent;
		this.agentVersion = agentVersion;
		this.device = device;
		this.ipAddress = ipAddress;
		this.customContext = Collections.unmodifiableMap(customContext);
	}

	/** Get the operating system, if supplied.
	 * @return the operating system.
	 */
	public Optional<String> getOS() {
		return os;
	}

	/** Get the version of the operating system, if supplied.
	 * @return the operating system version.
	 */
	public Optional<String> getOSVersion() {
		return osVersion;
	}

	/** Get the user agent (often a web browser), if supplied.
	 * @return the user agent.
	 */
	public Optional<String> getAgent() {
		return agent;
	}

	/** Get the version of the user agent, if supplied.
	 * @return the user agent version.
	 */
	public Optional<String> getAgentVersion() {
		return agentVersion;
	}

	/** Get the device (often a phone model), if supplied.
	 * @return the device.
	 */
	public Optional<String> getDevice() {
		return device;
	}

	/** Get the IP address, if supplied.
	 * @return the IP address.
	 */
	public Optional<InetAddress> getIpAddress() {
		return ipAddress;
	}

	/** Get any custom context supplied at the time of token creation.
	 * @return the custom context.
	 */
	public Map<String, String> getCustomContext() {
		return customContext;
	}

	/** Get a builder for the token creation context.
	 * @return a new builder.
	 */
	public static Builder getBuilder() {
		return new Builder();
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((agent == null) ? 0 : agent.hashCode());
		result = prime * result + ((agentVersion == null) ? 0 : agentVersion.hashCode());
		result = prime * result + ((customContext == null) ? 0 : customContext.hashCode());
		result = prime * result + ((device == null) ? 0 : device.hashCode());
		result = prime * result + ((ipAddress == null) ? 0 : ipAddress.hashCode());
		result = prime * result + ((os == null) ? 0 : os.hashCode());
		result = prime * result + ((osVersion == null) ? 0 : osVersion.hashCode());
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
		if (agent == null) {
			if (other.agent != null) {
				return false;
			}
		} else if (!agent.equals(other.agent)) {
			return false;
		}
		if (agentVersion == null) {
			if (other.agentVersion != null) {
				return false;
			}
		} else if (!agentVersion.equals(other.agentVersion)) {
			return false;
		}
		if (customContext == null) {
			if (other.customContext != null) {
				return false;
			}
		} else if (!customContext.equals(other.customContext)) {
			return false;
		}
		if (device == null) {
			if (other.device != null) {
				return false;
			}
		} else if (!device.equals(other.device)) {
			return false;
		}
		if (ipAddress == null) {
			if (other.ipAddress != null) {
				return false;
			}
		} else if (!ipAddress.equals(other.ipAddress)) {
			return false;
		}
		if (os == null) {
			if (other.os != null) {
				return false;
			}
		} else if (!os.equals(other.os)) {
			return false;
		}
		if (osVersion == null) {
			if (other.osVersion != null) {
				return false;
			}
		} else if (!osVersion.equals(other.osVersion)) {
			return false;
		}
		return true;
	}

	/** A builder for a token creation context.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private static final int MAX_CUSTOM_CONTEXT_MAP_ENTRIES = 100;
		private static final int MAX_CUSTOM_CONTEXT_VALUE_LENGTH = 80;
		private static final int MAX_CUSTOM_CONTEXT_KEY_LENGTH = 20;
		
		private Optional<String> os = Optional.empty();
		private Optional<String> osVersion = Optional.empty();
		private Optional<String> agent = Optional.empty();
		private Optional<String> agentVersion = Optional.empty();
		private Optional<String> device = Optional.empty();
		private Optional<InetAddress> ipAddress = Optional.empty();
		private Map<String, String> customContext = new HashMap<>();
		
		private Builder() {};
		
		/** Add an operating system to the context. If the operating system is null or whitespace
		 * only, the operating system and version are set to absent. If the version is null or
		 * whitespace only, the operating system will be set as provided and the version set to
		 * absent.
		 * @param os the operating system.
		 * @param version the operating system version.
		 * @return this builder.
		 */
		public Builder withNullableOS(final String os, final String version) {
			if (os == null || os.trim().isEmpty()) {
				this.os = Optional.empty();
				osVersion = Optional.empty();
				return this;
			}
			this.os = Optional.of(os);
			if (version == null || version.trim().isEmpty()) {
				osVersion = Optional.empty();
				return this;
			}
			osVersion = Optional.of(version);
			return this;
		}
		
		/** Add an agent to the context. If the agent is null or whitespace
		 * only, the agent and version are set to absent. If the version is null or
		 * whitespace only, the agent will be set as provided and the version set to
		 * absent.
		 * @param agent the agent.
		 * @param version the agent version.
		 * @return this builder.
		 */
		public Builder withNullableAgent(final String agent, final String version) {
			if (agent == null || agent.trim().isEmpty()) {
				this.agent = Optional.empty();
				agentVersion = Optional.empty();
				return this;
			}
			this.agent = Optional.of(agent);
			if (version == null || version.trim().isEmpty()) {
				agentVersion = Optional.empty();
				return this;
			}
			agentVersion = Optional.of(version);
			return this;
		}
		
		/** Add a device to the context. If the device is null or whitespace only the device is
		 * set to absent.
		 * @param device the device.
		 * @return return this builder.
		 */
		public Builder withNullableDevice(final String device) {
			if (device == null || device.trim().isEmpty()) {
				this.device = Optional.empty();
			} else {
				this.device = Optional.of(device);
			}
			return this;
		}
		
		/** Add an IP address to the context.
		 * @param ipAddress the IP address.
		 * @return this builder.
		 */
		public Builder withIpAddress(final InetAddress ipAddress) {
			requireNonNull(ipAddress, "ipAddress");
			this.ipAddress = Optional.of(ipAddress);
			return this;
		}
		
		/** Add an IP address that might be null to the context. If the address is null, the
		 * IP address is set to absent.
		 * @param ipAddress the IP address.
		 * @return this builder.
		 */
		public Builder withNullableIpAddress(final InetAddress ipAddress) {
			if (ipAddress == null) {
				this.ipAddress = Optional.empty();
			} else {
				this.ipAddress = Optional.of(ipAddress);
			}
			return this;
		}
		
		/** Add custom context to the token creation context. The context key must no more than
		 * 20 unicode code points and the value no more than 80. At most 100 key/value pairs can
		 * be added to the context.
		 * @param key the key of the key/value pair.
		 * @param value the value of the key/value pair.
		 * @return this builder.
		 * @throws MissingParameterException if the key or value is null or whitespace only.
		 * @throws IllegalParameterException if the key or value is too long, or too many
		 * key/value pairs are added to the context.
		 */
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
		
		/** Build the token creation context.
		 * @return token creation context.
		 */
		public TokenCreationContext build() {
			return new TokenCreationContext(
					os, osVersion, agent, agentVersion, device, ipAddress, customContext);
		}
	}
	
	

}

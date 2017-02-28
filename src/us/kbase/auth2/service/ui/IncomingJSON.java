package us.kbase.auth2.service.ui;

import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.google.common.base.Optional;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class IncomingJSON {

	// TODO JAVADOC
	// TODO TEST

	private final Map<String, Object> additionalProperties = new TreeMap<>();

	// don't throw error from constructor, doesn't get picked up by the custom error handler 
	protected IncomingJSON() {}

	protected UUID getUUID(final String uuid, final String fieldName)
			throws IllegalParameterException, MissingParameterException {
		if (uuid == null) {
			throw new MissingParameterException(fieldName + " field is required");
		}
		try {
			return UUID.fromString(uuid);
		} catch (IllegalArgumentException e) {
			throw new IllegalParameterException(fieldName + " is not a valid UUID: " + uuid);
		}
	}
	
	protected Optional<UUID> getOptionalUUID(final String uuid, final String fieldName)
			throws IllegalParameterException {
		if (uuid == null || uuid.trim().isEmpty()) {
			return Optional.absent();
		}
		try {
			return Optional.of(UUID.fromString(uuid));
		} catch (IllegalArgumentException e) {
			throw new IllegalParameterException(fieldName + " is not a valid UUID: " + uuid);
		}
	}

	protected boolean getBoolean(final Object b, final String fieldName)
			throws IllegalParameterException {
		if (b == null) {
			return false;
		}
		if (!(b instanceof Boolean)) {
			throw new IllegalParameterException(fieldName + " must be a boolean");
		}
		// may need to configure response for null
		return Boolean.TRUE.equals(b) ? true : false;
	}

	@JsonAnyGetter
	public Map<String, Object> getAdditionalProperties() {
		return this.additionalProperties;
	}

	@JsonAnySetter
	public void setAdditionalProperties(String name, Object value) {
		this.additionalProperties.put(name, value);
	}

	public void exceptOnAdditionalProperties() throws IllegalParameterException {
		if (!additionalProperties.isEmpty()) {
			throw new IllegalParameterException("Unexpected parameters in request: " + 
					String.join(", ", additionalProperties.keySet()));
		}
	}

}

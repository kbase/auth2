package us.kbase.auth2.service.ui;

import static us.kbase.auth2.lib.Utils.checkString;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class CreateTokenParams {

	private final String name;
	private final String type;
	
	@JsonCreator
	private CreateTokenParams(
			@JsonProperty("name") final String name,
			@JsonProperty("type") final String type)
			throws MissingParameterException {
		checkString(name, "name");
		checkString(type, "type");
		this.name = name;
		this.type = type;
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}
	
}

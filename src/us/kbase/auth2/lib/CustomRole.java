package us.kbase.auth2.lib;

import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class CustomRole {
	
	private final String id;
	private final String desc;
	
	//TODO ROLES The id should be sanity checked for length and url safety. Note that the id is permanent.
	//TODO ZLATER ROLES remove role from all users function
	//TODO ROLES note in documentation that the role description is arbitrary text and should be html escaped before display
	
	public CustomRole(final String id, final String desc)
			throws MissingParameterException {
		super();
		if (id == null || id.trim().isEmpty()) {
			throw new MissingParameterException("id");
		}
		if (desc == null || desc.trim().isEmpty()) {
			throw new MissingParameterException("desc");
		}
		this.id = id.trim();
		this.desc = desc.trim();
	}

	public String getID() {
		return id;
	}

	public String getDesc() {
		return desc;
	}

}

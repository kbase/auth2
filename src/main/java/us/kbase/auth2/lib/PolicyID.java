package us.kbase.auth2.lib;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** The ID for a policy document to which the user has agreed.
 * @author gaprice@lbl.gov
 *
 */
public class PolicyID extends Name {

	/** Create a policy ID.
	 * @param policyID the id.
	 * @throws MissingParameterException if the policy ID is missing.
	 * @throws IllegalParameterException if the policy ID is too long or contains control
	 * characters.
	 */
	public PolicyID(final String policyID)
			throws MissingParameterException, IllegalParameterException {
		super(policyID, "policy id", 20);
	}
}

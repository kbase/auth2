package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.base.Optional;

/** A specification for how a user search should be conducted.
 * 
 * If a search prefix or regex is supplied and neither withSearchOnUserName() nor
 * withSearchOnDisplayName() are called with a true argument then both fields are treated as search
 * targets.
 * 
 * A regex can only be set by code in the same package as this class.
 * @author gaprice@lbl.gov
 *
 */
public class UserSearchSpec {
	
	//TODO ZLATER CODE don't expose regex externally. Not sure how best to do this without duplicating a lot of the class. For now setting regex is default access (package only).
	
	private Optional<String> prefix = Optional.absent();
	private boolean searchUser = false;
	private boolean searchDisplayName = false;
	private final Set<Role> searchRoles = new HashSet<>();
	private final Set<String> searchCustomRoles = new HashSet<>();
	private boolean isRegex = false;
	
	private UserSearchSpec() {}

	/** Returns the user and/or display name prefix or regex for the search, if any.
	 * The prefix matches the start of the username or the start of any part of the whitespace
	 * tokenized display name.
	 * 
	 * A regex should be applied as is. isRegex() will be true if the prefix is actually a regex.
	 * @return the search prefix.
	 */
	public Optional<String> getSearchPrefix() {
		return prefix;
	}
	
	/** Returns true if a search prefix is set and that prefix should be treated as a regular
	 * expression rather than just a prefix, false otherwise.
	 * @return true if the search prefix is a regex
	 */
	public boolean isRegex() {
		return isRegex;
	}

	/** Returns true if a search should occur on the user's user name.
	 * 
	 * True when a) a prefix or regex is provided and b) withSearchOnUserName() was called with a
	 * true argument or neither searchOnUserName() nor searchOnDisplayName() were called with a
	 * true argument.
	 * @return whether the search should occur on the user's user name with the provided prefix or
	 * regex.
	 */
	public boolean isUserNameSearch() {
		return searchUser || (prefix.isPresent() && !searchDisplayName);
	}

	/** Returns true if a search should occur on the user's tokenized display name.
	 * 
	 * True when a) a prefix or regex is provided and b) withSearchOnDisplayName() was called with
	 * a true argument or neither searchOnUserName() nor searchOnDisplayName() were called with a
	 * true argument.
	 * @return whether the search should occur on the users's display name with the provided
	 * prefix or regex.
	 */
	public boolean isDisplayNameSearch() {
		return searchDisplayName || (prefix.isPresent() && !searchUser);
	}
	
	/** Returns true if a search should occur on the user's roles.
	 * @return true if the user's roles should be searched (e.g. getSearchRoles() returns at least
	 * one role).
	 */
	public boolean isRoleSearch() {
		return !searchRoles.isEmpty();
	}
	
	/** Returns true if a search should occur on the user's custom roles.
	 * @return true if the user's custom roles should be searched (e.g. getSearchCustomRoles()
	 * returns at least one role).
	 */
	public boolean isCustomRoleSearch() {
		return !searchCustomRoles.isEmpty();
	}

	/** Return the roles by which the search should be filtered.
	 * @return the roles which the returned users must possess.
	 */
	public Set<Role> getSearchRoles() {
		return Collections.unmodifiableSet(searchRoles);
	}

	/** Return the custom roles by which the search should be filtered.
	 * @return the custom roles which the returned users must possess.
	 */
	public Set<String> getSearchCustomRoles() {
		return Collections.unmodifiableSet(searchCustomRoles);
	}
	
	/** Returns the field by which users should be ordered when applying a limit.
	 * 
	 * Returns the first field for which the is*Search() method returns true, in the order:
	 * user name, display name, custom role, role.
	 * If no methods return true, returns the user name field.
	 * @return a search field on which the returned users should be sorted.
	 */
	public SearchField orderBy() {
		if (isUserNameSearch()) {
			return SearchField.USERNAME;
		}
		if (isDisplayNameSearch()) {
			return SearchField.DISPLAYNAME;
		}
		if (isCustomRoleSearch()) {
			return SearchField.CUSTOMROLE;
		}
		if (isRoleSearch()) {
			return SearchField.ROLE;
		}
		return SearchField.USERNAME;
	}
	
	/** A field on which to conduct a search.
	 * @author gaprice@lbl.gov
	 *
	 */
	public enum SearchField {
		/** The user's user name. */
		USERNAME,
		/** The user's display name. */
		DISPLAYNAME,
		/** A role possessed by a user. */
		ROLE,
		/** A custom role possessed by a user. */
		CUSTOMROLE;
	}
	
	/** Get a builder for building a UserSearchSpec.
	 * @return a UserSearchSpec builder.
	 */
	public static Builder getBuilder() {
		return new Builder();
	}

	/** A builder for a UserSearchSpec.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private UserSearchSpec uss = new UserSearchSpec();
		
		private Builder() {}
		
		/** Set a prefix by which the user name and / or tokenized display name will be searched.
		 * The prefix will replace the search regex, if any.
		 * The prefix matches the start of the username or the start of any part of the whitespace
		 * tokenized display name.
		 * The prefix is always converted to lower case.
		 * Once the prefix or search regex is set in this builder it cannot be removed.
		 * @param prefix the prefix.
		 * @return this builder.
		 */
		public Builder withSearchPrefix(final String prefix) {
			if (prefix == null || prefix.trim().isEmpty()) {
				throw new IllegalArgumentException("Prefix cannot be null or the empty string");
			}
			uss.prefix = Optional.of(prefix.toLowerCase());
			uss.isRegex = false;
			return this;
		}
		
		/** Set a regex by which the user name and / or tokenized display name will be searched.
		 * The regex will replace the search prefix, if any.
		 * Once the regex or search prefix is set in this builder it cannot be removed.
		 * 
		 * Be careful when sourcing a regex from user input. No safety measures are taken to
		 * prevent misuse of the regex.
		 * @param regex the regex.
		 * @return this builder.
		 */
		Builder withSearchRegex(final String regex) {
			if (regex == null || regex.trim().isEmpty()) {
				throw new IllegalArgumentException("Regex cannot be null or the empty string");
			}
			uss.prefix = Optional.of(regex);
			uss.isRegex = true;
			return this;
		}
		
		/** Specify whether a search on a users's user name should occur.
		 * A prefix must be set prior to calling this method.
		 * @param search whether the search should occur on the user's user name.
		 * @return this builder.
		 */
		public Builder withSearchOnUserName(final boolean search) {
			checkSearchPrefix(search);
			uss.searchUser = search;
			return this;
		}
		
		/** Specify whether a search on a users's display name should occur.
		 * A prefix must be set prior to calling this method.
		 * @param search whether the search should occur on the user's display name.
		 * @return this builder.
		 */
		public Builder withSearchOnDisplayName(final boolean search) {
			checkSearchPrefix(search);
			uss.searchDisplayName = search;
			return this;
		}

		private void checkSearchPrefix(final boolean search) {
			if (search && !uss.prefix.isPresent()) {
				throw new IllegalStateException(
						"Must provide a prefix if a name search is to occur");
			}
		}
		
		/** Add a role by which the search should be filtered.
		 * Multiple roles may be added via multiple method invocations.
		 * A user must have all of the roles to be included in the search results.
		 * @param role the role to add to the set of required roles.
		 * @return this builder.
		 */
		public Builder withSearchOnRole(final Role role) {
			nonNull(role, "role");
			uss.searchRoles.add(role);
			return this;
		}
		
		/** Add a custom role by which the search should be filtered.
		 * Multiple roles may be added via multiple method invocations.
		 * A user must have all of the custom roles to be included in the search results.
		 * @param customRole the custom role to add to the set of required roles.
		 * @return this builder.
		 */
		public Builder withSearchOnCustomRole(final String customRole) {
			if (customRole == null || customRole.trim().isEmpty()) {
				throw new IllegalArgumentException(
						"Custom role cannot be null or the empty string");
			}
			uss.searchCustomRoles.add(customRole);
			return this;
		}
		
		/** Build a UserSearchSpec instance.
		 * @return a UserSearchSpec.
		 */
		public UserSearchSpec build() {
			return uss;
		}
	}
	
}

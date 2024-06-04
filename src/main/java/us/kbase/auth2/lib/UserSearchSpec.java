package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;

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
	
	private final List<String> userNamePrefixes;
	private final List<String> displayPrefixes;
	private final String regex;
	private final boolean searchUser;
	private final boolean searchDisplayName;
	private final Set<Role> searchRoles;
	private final Set<String> searchCustomRoles;
	private final boolean includeRoot;
	private final boolean includeDisabled;

	private UserSearchSpec(
			final List<String> userNamePrefixes,
			final List<String> displayPrefixes,
			final String regex,
			final boolean searchUser,
			final boolean searchDisplayName,
			final Set<Role> searchRoles,
			final Set<String> searchCustomRoles,
			final boolean includeRoot,
			final boolean includeDisabled) {
		this.userNamePrefixes = userNamePrefixes == null ? null :
				Collections.unmodifiableList(userNamePrefixes);
		this.displayPrefixes = displayPrefixes == null ? null :
				Collections.unmodifiableList(displayPrefixes);
		this.regex = regex;
		this.searchUser = searchUser;
		this.searchDisplayName = searchDisplayName;
		this.searchRoles = searchRoles;
		this.searchCustomRoles = searchCustomRoles;
		this.includeRoot = includeRoot;
		this.includeDisabled = includeDisabled;
	}

	/** Returns the user name prefixes for the search, if any.
	 * The prefixes match the start of the user name.
	 * @return the search prefix.
	 */
	public List<String> getSearchUserNamePrefixes() {
		return userNamePrefixes == null ? Collections.emptyList() : userNamePrefixes;
	}
	
	/** Returns the display name prefixes for the search, if any.
	 * The prefixes match the start of any part of the whitespace
	 * tokenized display name.
	 * @return the search prefix.
	 */
	public List<String> getSearchDisplayPrefixes() {
		return displayPrefixes == null ? Collections.emptyList() : displayPrefixes;
	}
	
	/** Returns the user and/or display name regex for the search, if any.
	 * A regex should be applied as is.
	 * @return the search prefix.
	 */
	public Optional<String> getSearchRegex() {
		return Optional.ofNullable(regex);
	}
	
	/** Returns true if the regex is set. This means the search prefix is not set.
	 * @return true if the regex is set.
	 */
	public boolean hasSearchRegex() {
		return regex != null;
	}
	
	/** Returns true if the search prefixes are set. This means the search regex is not set.
	 * @return true if the search prefixes are set.
	 */
	public boolean hasSearchPrefixes() {
		return displayPrefixes != null;
	}
	
	/** Returns true if a search should occur on the user's user name.
	 * 
	 * True when
	 * a) a prefix with a valid format for a username or regex is provided and
	 * b) withSearchOnUserName() was called with a true argument or neither or both of
	 * withSearchOnUserName() and withSearchOnDisplayName() were called with a true argument.
	 * @return whether the search should occur on the user's user name with the provided prefix or
	 * regex.
	 */
	public boolean isUserNameSearch() {
		return (regex != null || userNamePrefixes != null) && (searchUser || !searchDisplayName);
	}

	/** Returns true if a search should occur on the user's tokenized display name.
	 * 
	 * True when
	 * a) a prefix or regex is provided and
	 * b) withSearchOnDisplayName() was called with a true argument or neither or both of
	 * withSearchOnUserName() and withSearchOnDisplayName() were called with a true argument.
	 * @return whether the search should occur on the users's display name with the provided
	 * prefix or regex.
	 */
	public boolean isDisplayNameSearch() {
		return (regex != null || displayPrefixes != null) && (searchDisplayName || !searchUser);
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
	
	/** Returns true if the root user should be included in the search results if warranted.
	 * @return true if the root user should be included.
	 */
	public boolean isRootIncluded() {
		return includeRoot;
	}
	
	/** Returns true if disabled users should be included in the search results if warranted.
	 * @return true if disabled users should be included.
	 */
	public boolean isDisabledIncluded() {
		return includeDisabled;
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

	@Override
	public int hashCode() {
		return Objects.hash(displayPrefixes, includeDisabled, includeRoot, regex,
				searchCustomRoles, searchDisplayName, searchRoles, searchUser, userNamePrefixes);
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
		UserSearchSpec other = (UserSearchSpec) obj;
		return Objects.equals(displayPrefixes, other.displayPrefixes)
				&& includeDisabled == other.includeDisabled
				&& includeRoot == other.includeRoot
				&& Objects.equals(regex, other.regex)
				&& Objects.equals(searchCustomRoles, other.searchCustomRoles)
				&& searchDisplayName == other.searchDisplayName
				&& Objects.equals(searchRoles, other.searchRoles)
				&& searchUser == other.searchUser
				&& Objects.equals(userNamePrefixes, other.userNamePrefixes);
	}

	/** A builder for a UserSearchSpec.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private String prefix;
		private String regex = null;
		private boolean searchUser = false;
		private boolean searchDisplayName = false;
		private final Set<Role> searchRoles = new HashSet<>();
		private final Set<String> searchCustomRoles = new HashSet<>();
		private boolean includeRoot = false;
		private boolean includeDisabled = false;
		
		private Builder() {}
		
		/** Set a prefix by which the user name and / or tokenized display name will be searched.
		 * The prefix will replace the search regex, if any.
		 * The prefix matches the start of the username or the start of any part of the whitespace
		 * and hyphen tokenized display name.
		 * The user name prefix is split by whitespace and all illegal characters removed.
		 * The display name prefix is split by whitespace and hyphens, punctuation removed,
		 * and converted to lower case.
		 * Once the prefix or search regex is set in this builder it cannot be removed.
		 * @param prefix the prefix.
		 * @return this builder.
		 */
		public Builder withSearchPrefix(final String prefix) {
			checkStringNoCheckedException(prefix, "prefix");
			this.prefix = prefix;
			this.regex = null;
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
			this.regex = checkStringNoCheckedException(regex, "regex");
			this.prefix = null;
			return this;
		}
		
		/** Specify whether a search on a users's user name should occur.
		 * A prefix must be set prior to calling this method.
		 * If neither a user nor a display search is set (the default) and a prefix is set, then
		 * the search occurs on both fields.
		 * @param search whether the search should occur on the user's user name.
		 * @return this builder.
		 */
		public Builder withSearchOnUserName(final boolean search) {
			checkSearchPrefix(search);
			this.searchUser = search;
			return this;
		}
		
		/** Specify whether a search on a users's display name should occur.
		 * A prefix must be set prior to calling this method.
		 * If neither a user nor a display search is set (the default) and a prefix is set, then
		 * the search occurs on both fields.
		 * @param search whether the search should occur on the user's display name.
		 * @return this builder.
		 */
		public Builder withSearchOnDisplayName(final boolean search) {
			checkSearchPrefix(search);
			this.searchDisplayName = search;
			return this;
		}

		private void checkSearchPrefix(final boolean search) {
			if (search && prefix == null && regex == null) {
				throw new IllegalStateException(
						"Must provide a prefix or regex if a name search is to occur");
			}
		}
		
		/** Add a role by which the search should be filtered.
		 * Multiple roles may be added via multiple method invocations.
		 * A user must have all of the roles to be included in the search results.
		 * @param role the role to add to the set of required roles.
		 * @return this builder.
		 */
		public Builder withSearchOnRole(final Role role) {
			requireNonNull(role, "role");
			this.searchRoles.add(role);
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
			this.searchCustomRoles.add(customRole);
			return this;
		}
		
		/** Include the root user in the search results, if warranted.
		 * @param include true to include the root user.
		 * @return this builder.
		 */
		public Builder withIncludeRoot(final boolean include) {
			this.includeRoot = include;
			return this;
		}
		
		/** Include disabled users in the search results, if warranted.
		 * @param include true to include disabled users.
		 * @return this builder.
		 */
		public Builder withIncludeDisabled(final boolean include) {
			this.includeDisabled = include;
			return this;
		}
		
		/** Build a UserSearchSpec instance.
		 * @return a UserSearchSpec.
		 * @throws IllegalParameterException if a prefix is set that, after normalizing, contains
		 * no characters for the requested search(es).
		 */
		public UserSearchSpec build() throws IllegalParameterException {
			List<String> userNamePrefixes = null;
			List<String> displayPrefixes = null;
			if (this.prefix != null) {
				/*	UsrSrch	DisSrch	UsrOK	DisOK	Throw exception?
				 *	T		T		Y implies Y		
				 *	T		T		No		Y		No, just go with display search
				 *	T		T		No		No		Display or user exception
				 *
				 *	T		F		Y implies Y		
				 *	T		F		No		Y		User exception
				 *	T		F		No		No		User exception
				 *
				 *	F		T		Y implies Y		
				 * 	F		T		No		Y		
				 * 	F		T		No		No		Display exception
				 * 
				 * Note that:
				 *   * If the user search is ok (UsrOK) the display search must be ok since the
				 *     user search has at least one a-z char.
				 *   * The first block where UsrSrch and DisSrch are all true is equivalent
				 *     to a block where they're all false, and so that block is omitted.
				 */
				userNamePrefixes = UserName.getCanonicalNames(prefix);
				userNamePrefixes = userNamePrefixes.isEmpty() ? null : userNamePrefixes;
				displayPrefixes = DisplayName.getCanonicalDisplayName(prefix);
				displayPrefixes = displayPrefixes.isEmpty() ? null : displayPrefixes;
				if (searchUser && !searchDisplayName && userNamePrefixes == null) {
					throw new IllegalParameterException(String.format(
							"The search prefix %s contains no valid username prefix "
									+ "and a user name search was requested", this.prefix));
				}
				if (displayPrefixes == null) {
					throw new IllegalParameterException(String.format(
							"The search prefix %s contains only punctuation and a "
							+ "display name search was requested", this.prefix));
				}
			}
			return new UserSearchSpec(userNamePrefixes, displayPrefixes, regex, searchUser,
					searchDisplayName, searchRoles, searchCustomRoles,
					includeRoot, includeDisabled);
		}
	}
}

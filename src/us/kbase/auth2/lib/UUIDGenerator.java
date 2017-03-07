package us.kbase.auth2.lib;

import java.util.UUID;

// maybe use PowerMock instead?

/** An interface for generating UUIDs. Only used for testing purposes.
 * @author gaprice@lbl.gov
 *
 */

public interface UUIDGenerator {
	UUID randomUUID();
}

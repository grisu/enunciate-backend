package grisu.control;

import org.globus.common.CoGProperties;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class GrisuUserDetailsImpl implements UserDetailsService {

	// static final Logger myLogger =
	// Logger.getLogger(GrisuUserDetailsImpl.class
	// .getName());

	static {
		CoGProperties.getDefault().setProperty(
				CoGProperties.ENFORCE_SIGNING_POLICY, "false");
	}

	public UserDetails loadUserByUsername(String arg0)
			throws UsernameNotFoundException, DataAccessException {

		// myLogger.debug("Authenticating....");
		return new GrisuUserDetails(arg0);

	}

}

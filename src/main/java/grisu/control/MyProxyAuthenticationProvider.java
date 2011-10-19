package grisu.control;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MyProxyAuthenticationProvider extends DaoAuthenticationProvider {

	static final Logger myLogger = Logger
			.getLogger(MyProxyAuthenticationProvider.class.getName());

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)
					throws AuthenticationException {

		// System.out.println("MyProxy: ");
		// System.out.println("Username: "
		// + authentication.getPrincipal().toString());

		final GrisuUserDetails gud = (GrisuUserDetails) userDetails;
		gud.setAuthentication(authentication);

	}

}

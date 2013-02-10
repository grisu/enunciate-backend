package grisu.control;

import grisu.backend.model.User;
import grisu.control.exceptions.NoValidCredentialException;
import grisu.control.serviceInterfaces.AbstractServiceInterface;
import grisu.settings.ServerPropertiesManager;
import grith.jgrith.cred.AbstractCred;
import grith.jgrith.cred.MyProxyCred;
import grith.jgrith.utils.CertHelpers;

import java.util.Date;
import java.util.Set;

import net.sf.ehcache.Element;

import org.apache.commons.lang.StringUtils;
import org.globus.myproxy.CredentialInfo;
import org.globus.myproxy.MyProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;

import com.google.common.collect.Sets;


public class GrisuUserDetails implements UserDetails {

	static final Logger myLogger = LoggerFactory
			.getLogger(GrisuUserDetails.class.getName());
	
	static final String IMPERSONATE_STRING = "=impersonate=";


	private final String username;
	private UsernamePasswordAuthenticationToken authentication;
	private final boolean success = true;
	private AbstractCred proxy = null;

	private Date lastProxyRetrieve = null;

	private User user = null;

	private final String myproxyHost = ServerPropertiesManager.getMyProxyHost();
	private final int myproxyPort = ServerPropertiesManager.getMyProxyPort();

	public GrisuUserDetails(String username) {
		myLogger.debug("Creating GrisuUserDetails object for " + username);
		this.username = username;
	}

	private synchronized AbstractCred createProxyCredential(String username,
			String password, String myProxyServer, int port, int lifetime) {

		// System.out.println("Username: "+username);
		// System.out.println("Password: "+password);

		// final MyProxy myproxy = new MyProxy(myProxyServer, port);
		try {
			myLogger.debug("Getting delegated proxy from MyProxy...");
			AbstractCred cred = new MyProxyCred(username, password.toCharArray(), myProxyServer, port, lifetime, false, false);
//			cred.init();
			// proxy = myproxy.get(username, password, lifetime);
			final int remaining = cred.getRemainingLifetime();
			myLogger.debug("Finished getting delegated proxy from MyProxy. DN: "
					+ CertHelpers.getDnInProperFormat(cred.getGSSCredential())
					+ " remaining liftime: " + remaining);

			if (remaining <= 0) {
				throw new RuntimeException("Proxy not valid anymore.");
			}

			return cred;
			// return new Credential(proxy);
		} catch (final Exception e) {
			myLogger.error(
					"Could not create myproxy credential: "
							+ e.getLocalizedMessage(), e);
			throw new NoValidCredentialException(e.getLocalizedMessage());
		}

	}


	public synchronized AbstractCred fetchCredential()
			throws AuthenticationException {

		// myLogger.debug("Getting proxy credential...");

		if (authentication == null) {
			throw new AuthenticationException("No authentication token set.") {
			};
		}

		if ((proxy != null) && proxy.isValid()) {

			// myLogger.debug("Old valid proxy found.");
			long oldLifetime = -1;
			try {
				oldLifetime = proxy.getGSSCredential().getRemainingLifetime();
				if (oldLifetime >= ServerPropertiesManager
						.getMinProxyLifetimeBeforeGettingNewProxy()) {

					// myLogger.debug("Proxy still valid and long enough lifetime.");
					// myLogger.debug("Old valid proxy still good enough. Using it.");
					return proxy;
				}

				// only get the proxy every xx minutes if valid but not within
				// remaining liftime threshold anymore
				if (lastProxyRetrieve != null) {
					long lastTime = lastProxyRetrieve.getTime();
					long now = new Date().getTime();

					long diff = ServerPropertiesManager
							.getWaitTimeBetweenProxyRetrievals() * 1000;

					if ((lastTime + diff) >= now) {
						return proxy;
					}
				}

			} catch (final Exception e) {
				myLogger.error(e.getLocalizedMessage(), e);
			}
			// myLogger.debug("Old proxy not good enough. Creating new one...");
		}

		AbstractCred proxyTemp = null;

		String username = authentication.getPrincipal().toString();
		String password = authentication.getCredentials().toString();

		String host = null;

		int index = username.lastIndexOf('@');

		if ((index > 0) && (index < username.length())) {
			host = username.substring(index + 1);
			username = username.substring(0, index);
		}
		
		String impersonateDN = null;
		if ( username.contains("=impersonate=") ) {
			int i = username.indexOf(IMPERSONATE_STRING);
			impersonateDN = username.substring(i+IMPERSONATE_STRING.length());
			username = username.substring(0, i);
			
			if (!User.isRemoteAccessAllowed(impersonateDN)) {
				throw new AuthenticationException("User does not allow remote support: "+impersonateDN) {};
			}
		}

		int port = ServerPropertiesManager.getMyProxyPort();
		if (StringUtils.isBlank(host)) {
			host = ServerPropertiesManager.getMyProxyHost();
		}

		try {
			proxyTemp = createProxyCredential(username, password, host, port,
					ServerPropertiesManager.getMyProxyLifetime());
			Element element = new Element(proxyTemp.getDN(), proxyTemp);
			AbstractServiceInterface.eternalCache().put(element);
			lastProxyRetrieve = new Date();
		} catch (final NoValidCredentialException e) {
			throw new AuthenticationException(e.getLocalizedMessage(), e) {
			};
		}

		if ((proxyTemp == null) || !proxyTemp.isValid()) {

			throw new AuthenticationException(
					"Could not get valid myproxy credential.") {
			};
		} else {
			// myLogger.info("Authentication successful.");
			if ( StringUtils.isNotBlank(impersonateDN) ) {
				
				myLogger.info("Impersonation attempt from "+proxyTemp.getDN()+": requested user = "+impersonateDN);
				
				if ( ! AbstractServiceInterface.admin.isAdmin(proxyTemp.getDN()) ) {
					String msg = "Could not change identity to '"+impersonateDN+"', user not admin: "+proxyTemp.getDN();
					myLogger.info(msg);
					throw new AuthenticationException(msg){};
				}
				
				
				
				Element e = AbstractServiceInterface.eternalCache().get(impersonateDN);
				if ( e == null || e.getObjectValue() == null ) {
					
					// ok, let's see whether part of the string matches, and if it is a unique result, we'll use that
					Set<String> dns = Sets.newTreeSet();
					for (Object key : AbstractServiceInterface.eternalCache().getKeys() ) {
						String key_dn = (String)key;
						if ( key_dn.toLowerCase().contains(impersonateDN) ) {
							dns.add(key_dn);
						}
					}
					
					if ( dns.size() == 0 ) {
						String msg = "Could not find authentication token for: "+impersonateDN;
						myLogger.info(msg);
						throw new AuthenticationException(msg){};						
					} else if ( dns.size() > 1 ) {
						String msg = "Found multiple matches for impersonation token '"+impersonateDN+"': "+StringUtils.join(dns, ",");
						myLogger.info(msg);
						throw new AuthenticationException("msg"){};
					} else {
						e = AbstractServiceInterface.eternalCache().get(dns.iterator().next());
						if ( e == null || e.getObjectValue() == null ) {
							String msg = "Could not find authentication token for: "+dns.iterator().next();
							myLogger.info(msg);
							throw new AuthenticationException(msg){};						
						}
					}

				}
				this.proxy = (AbstractCred) e.getObjectValue();
				myLogger.info("Impersonation successful. Using dn: "+this.proxy.getDN());
			} else {
				this.proxy = proxyTemp;
				myLogger.info("Proxy creation successful. Using dn: "+this.proxy.getDN());
			}
			return this.proxy;
		}

	}

	public Set<GrantedAuthority> getAuthorities() {

		if (success) {
			final Set<GrantedAuthority> result = Sets.newHashSet();
			result.add(new GrantedAuthorityImpl("User"));
			return result;
		} else {
			return null;
		}

	}

	public synchronized long getCredentialEndTime() {

		if (authentication == null) {
			return -1;
		}

		final MyProxy myproxy = new MyProxy(
				ServerPropertiesManager.getMyProxyHost(),
				ServerPropertiesManager.getMyProxyPort());

		CredentialInfo info = null;
		try {
			final String user = authentication.getPrincipal().toString();
			final String password = authentication.getCredentials().toString();
			info = myproxy.info(fetchCredential().getGSSCredential(), user,
					password);
		} catch (final Exception e) {
			myLogger.error(e.getLocalizedMessage(), e);
			return -1;
		}

		return info.getEndTime();

	}

	public String getPassword() {

		return "dummy";
	}

	public synchronized User getUser(AbstractServiceInterface si) {

		if (user == null) {
			user = User.createUser(fetchCredential(), si);
		}

		user.setCredential(fetchCredential());
		return user;

	}

	public String getUsername() {
		return username;
	}

	public boolean isAccountNonExpired() {
		return success;
	}

	public boolean isAccountNonLocked() {
		return success;
	}

	public boolean isCredentialsNonExpired() {
		return success;
	}

	public boolean isEnabled() {
		return success;
	}

	public void setAuthentication(
			UsernamePasswordAuthenticationToken authentication) {
		if (this.authentication != null) {
			Object cred = this.authentication.getCredentials();

			if ((cred != null) && !cred.equals(authentication.getCredentials())) {
				this.proxy = null;
			}
		}

		this.authentication = authentication;
		fetchCredential();
	}



}

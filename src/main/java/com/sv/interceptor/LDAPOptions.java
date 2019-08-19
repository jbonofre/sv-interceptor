package com.sv.interceptor;

import org.apache.karaf.jaas.config.KeystoreManager;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceReference;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.ConfigurationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.net.ssl.SSLSocketFactory;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LDAPOptions {

    public static final String CONNECTION_URL = "connection.url";
    public static final String CONNECTION_USERNAME = "connection.username";
    public static final String CONNECTION_PASSWORD = "connection.password";
    public static final String CONNECTION_TIMEOUT= "connection.timeout";
    public static final String DEFAULT_CONNECTION_TIMEOUT = "1000";
    public static final String USER_BASE_DN = "user.base.dn";
    public static final String USER_FILTER = "user.filter";
    public static final String USER_SEARCH_SUBTREE = "user.search.subtree";
    public static final String ROLE_BASE_DN = "role.base.dn";
    public static final String ROLE_FILTER = "role.filter";
    public static final String ROLE_SEARCH_SUBTREE = "role.search.subtree";
    public static final String AUTHENTICATION = "authentication";
    public static final String DISABLE_CACHE = "disableCache";
    public static final String MAX_DEPTH= "ldap.maxDepth";
    public static final int DEFAULT_MAX_DEPTH= 2;
    public static final String INITIAL_CONTEXT_FACTORY = "initial.context.factory";
    public static final String CONTEXT_PREFIX = "context.";
    public static final String SSL = "ssl";
    public static final String SSL_PROVIDER = "ssl.provider";
    public static final String SSL_PROTOCOL = "ssl.protocol";
    public static final String SSL_ALGORITHM = "ssl.algorithm";
    public static final String SSL_KEYSTORE = "ssl.keystore";
    public static final String SSL_KEYALIAS = "ssl.keyalias";
    public static final String SSL_TRUSTSTORE = "ssl.truststore";
    public static final String SSL_TIMEOUT = "ssl.timeout";
    public static final String DEFAULT_INITIAL_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String DEFAULT_AUTHENTICATION = "simple";
    public static final int DEFAULT_SSL_TIMEOUT = 10;

    private static Logger LOGGER = LogManager.getLogger(LDAPOptions.class);

    private final Map<String, ?> options;

    public LDAPOptions(Dictionary<String, ?> dictionary) {
        Map<String, Object> map = new HashMap<>();
        Enumeration<String> keys = dictionary.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            Object value = dictionary.get(key);
            map.put(key, value);
        }
        this.options = new HashMap<>(map);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LDAPOptions that = (LDAPOptions) o;
        return options.equals(that.options);
    }

    @Override
    public int hashCode() {
        return options.hashCode();
    }

    public String getUserFilter() {
        return (String) options.get(USER_FILTER);
    }

    public String getUserBaseDn() {
        return (String) options.get(USER_BASE_DN);
    }

    public boolean getUserSearchSubtree() {
        return Boolean.parseBoolean((String) options.get(USER_SEARCH_SUBTREE));
    }

    public String getRoleFilter() {
        return (String) options.get(ROLE_FILTER);
    }

    public String getRoleBaseDn() {
        return (String) options.get(ROLE_BASE_DN);
    }

    public boolean getRoleSearchSubtree() {
        return Boolean.parseBoolean((String) options.get(ROLE_SEARCH_SUBTREE));
    }

    public Hashtable<String, Object> getEnv() throws NamingException {
        final Hashtable<String, Object> env = new Hashtable<>();
        for (String key : options.keySet()) {
            if (key.startsWith(CONTEXT_PREFIX)) {
                env.put(key.substring(CONTEXT_PREFIX.length()), options.get(key));
            }
        }
        env.put(Context.INITIAL_CONTEXT_FACTORY, getInitialContextFactory());

        env.put(Context.PROVIDER_URL, getConnectionURL());
        env.put("com.sun.jndi.ldap.connect.timeout", getConnectionTimeout());
        if (getConnectionUsername() != null && getConnectionUsername().trim().length() > 0) {
            String auth = getAuthentication();
            if (auth == null) {
                auth = DEFAULT_AUTHENTICATION;
            }
            env.put(Context.SECURITY_AUTHENTICATION, auth);
            env.put(Context.SECURITY_PRINCIPAL, getConnectionUsername());
            env.put(Context.SECURITY_CREDENTIALS, getConnectionPassword());
        } else if (getAuthentication() != null) {
            env.put(Context.SECURITY_AUTHENTICATION, getAuthentication());
        }
        if (getSsl()) {
            setupSsl(env);
        } else if (isLdaps()) {
            LOGGER.info("Use default trustore, handshake only");
        }
        return env;
    }

    protected void setupSsl(Hashtable<String, Object> env) throws NamingException {
        BundleContext bundleContext = FrameworkUtil.getBundle(LDAPOptions.class).getBundleContext();
        ServiceReference<KeystoreManager> ref = null;
        LOGGER.debug("Setting up SSL");
        try {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            env.put("java.naming.ldap.factory.socket", ManagedSSLSocketFactory.class.getName());
            ref = bundleContext.getServiceReference(KeystoreManager.class);
            KeystoreManager manager = bundleContext.getService(ref);
            SSLSocketFactory factory = manager.createSSLFactory(
                    getSslProvider(), getSslProtocol(), getSslAlgorithm(), getSslKeystore(),
                    getSslKeyAlias(), getSslTrustStore(), getSslTimeout());
            ManagedSSLSocketFactory.setSocketFactory(new ManagedSSLSocketFactory(factory));
            Thread.currentThread().setContextClassLoader(ManagedSSLSocketFactory.class.getClassLoader());
        } catch (Exception e) {
            throw new NamingException("Unable to setup SSL support for LDAP: " + e.getMessage());
        } finally {
            bundleContext.ungetService(ref);
        }
    }

    public Object getInitialContextFactory() {
        String initialContextFactory = (String) options.get(INITIAL_CONTEXT_FACTORY);
        if (initialContextFactory == null) {
            initialContextFactory = DEFAULT_INITIAL_CONTEXT_FACTORY;
        }
        return initialContextFactory;
    }

    public String getConnectionURL() throws ConfigurationException {
        String urlRegex = "ldaps?://[a-z0-9]+([\\-\\.]{1}[a-z0-9]+)*\\.[a-z]{2,5}(:[0-9]{1,5})?(\\/.*)?$";
        Pattern pattern = Pattern.compile(urlRegex);


        String connectionURL = (String) options.get(CONNECTION_URL);
        if (connectionURL == null || connectionURL.trim().length() == 0) {
            throw new ConfigurationException(CONNECTION_URL + " is empty.");
        }

        Matcher matcher = pattern.matcher(connectionURL);
        if (!matcher.matches()) {
            throw new ConfigurationException(CONNECTION_URL + " is invalid.");
        }
        return connectionURL;
    }

    public String getConnectionUsername() {
        return (String) options.get(CONNECTION_USERNAME);
    }

    public String getConnectionPassword() {
        return (String) options.get(CONNECTION_PASSWORD);
    }

    public String getConnectionTimeout() {
        Object val = options.get(CONNECTION_TIMEOUT);
        if (val != null) {
            return (String)val;
        } else {
            return DEFAULT_CONNECTION_TIMEOUT;
        }
    }

    public String getAuthentication() {
        return (String) options.get(AUTHENTICATION);
    }

    public boolean isLdaps() throws ConfigurationException {
        return getConnectionURL().startsWith("ldaps:");
    }

    public boolean getSsl() {
        Object val = options.get(SSL);
        if (val instanceof Boolean) {
            return (Boolean) val;
        } else if (val != null) {
            return Boolean.parseBoolean(val.toString());
        } else {
            return false;
        }
    }

    public String getSslProvider() {
        return (String) options.get(SSL_PROVIDER);
    }

    public String getSslProtocol() {
        return (String) options.get(SSL_PROTOCOL);
    }

    public String getSslAlgorithm() {
        return (String) options.get(SSL_ALGORITHM);
    }

    public String getSslKeystore() {
        return (String) options.get(SSL_KEYSTORE);
    }

    public String getSslKeyAlias() {
        return (String) options.get(SSL_KEYALIAS);
    }

    public String getSslTrustStore() {
        return (String) options.get(SSL_TRUSTSTORE);
    }

    public int getSslTimeout() {
        Object val = options.get(SSL_TIMEOUT);
        if (val instanceof Number) {
            return ((Number) val).intValue();
        } else if (val != null) {
            return Integer.parseInt(val.toString());
        } else {
            return DEFAULT_SSL_TIMEOUT;
        }
    }

    public int getMaxDepth() {
        Object val = options.get(MAX_DEPTH);
        if (val instanceof Number) {
            return ((Number) val).intValue();
        } else if (val != null) {
            return Integer.parseInt(val.toString());
        } else {
            return DEFAULT_MAX_DEPTH;
        }
    }

    public boolean getDisableCache() {
        final Object object = options.get(DISABLE_CACHE);
        return object != null && Boolean.parseBoolean((String) object);
    }

}
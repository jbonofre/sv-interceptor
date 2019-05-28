package com.sv.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utils to get the CXF buses defined in the configuration
 */
public class InterceptorsUtil {

    private Dictionary properties;

    private final static Logger LOGGER = LoggerFactory.getLogger(InterceptorsUtil.class);

    public InterceptorsUtil(Dictionary properties) {
        this.properties = properties;
    }


    /**
     * Get the roles defined for a given bus.
     *
     * @param symbolicName the CXF bus synbolic name (or prefix string) as defined in the configuration.
     * @return the list of roles defined for the bus.
     */
    private String[] getRoles(String symbolicName) throws Exception {
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                LOGGER.debug("Checking bus symbolic name {} on regex {}", symbolicName, key);
                Pattern pattern = Pattern.compile(key);
                Matcher matcher = pattern.matcher(symbolicName);
                if (matcher.matches()) {
                    String roles = (String) properties.get(key);
                    LOGGER.debug("Roles found for bus symbolic name {}: {}", symbolicName, roles);
                    return roles.split(",");
                }
            }
        }
        return null;
    }

    /**
     * Check if a bus ID is defined in the configuration
     *
     * @param name the CXF bus symbolic name
     * @return true if the bus is defined in the configuration, false else.
     */
    public Dictionary getMatchingRules(String name) throws Exception {
        Dictionary matchingRules = new Hashtable();
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                String symbolicName = key.split(":")[0];
                LOGGER.debug("Check matching with {}", symbolicName);
                Pattern pattern = Pattern.compile(symbolicName);
                Matcher matcher = pattern.matcher(name);
                if (matcher.matches()) {
                    matchingRules.put(key, properties.get(key));
                }
            }
        }


        return matchingRules;
    }

    /**
     * Check if one of the roles match the bus roles definition.
     *
     * @param symbolicName the bus bundle symbolic name.
     * @param roles the roles to check.
     * @return true if at least one of the role match, false else.
     */
    public boolean authorize(String symbolicName, List<String> roles) throws Exception {
        LOGGER.debug("Checking authorization for bus symbolic name {}", symbolicName);
        String[] configuredRoles = this.getRoles(symbolicName);
        if (configuredRoles != null) {
            for (String role : roles) {
                LOGGER.debug("Checking authorization for role {}", role);
                for (String configuredRole : configuredRoles) {
                    if (role.equalsIgnoreCase(configuredRole)) {
                        LOGGER.debug("Roles match ({}/{})", role, configuredRole);
                        return true;
                    } else {
                        LOGGER.debug("Roles not match ({}/{})", role, configuredRole);
                    }
                }
            }
        }
        return false;
    }

}
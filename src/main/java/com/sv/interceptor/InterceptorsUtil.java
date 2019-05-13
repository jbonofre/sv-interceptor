package com.sv.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.List;
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
     * Get the buses defined in the configuration.
     *
     * @return the list of bus ID defined
     */
    public List<String> getBuses() throws Exception {
        ArrayList<String> buses = new ArrayList<String>();
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                LOGGER.debug("Adding CXF bus {}", key);
                buses.add(key);
            }
        }
        return buses;
    }

    /**
     * Get the roles defined for a given bus.
     *
     * @param busId the CXF bus ID (or prefix string) as defined in the configuration.
     * @return the list of roles defined for the bus.
     */
    private String[] getBusRoles(String busId) throws Exception {
        if (properties != null) {
            Enumeration keys = properties.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                LOGGER.debug("Checking bus {} on regex {}", busId, key);
                Pattern pattern = Pattern.compile(key);
                Matcher matcher = pattern.matcher(busId);
                if (matcher.matches()) {
                    String roles = (String) properties.get(key);
                    LOGGER.debug("Roles found for CXF bus {}: {}", busId, roles);
                    return roles.split(",");
                }
            }
        }
        return null;
    }

    /**
     * Check if a bus ID is defined in the configuration
     *
     * @param id the CXF bus ID to check.
     * @return true if the bus is defined in the configuration, false else.
     */
    public boolean busDefined(String id) throws Exception {
        List<String> buses = this.getBuses();
        for (String bus : buses) {
            Pattern pattern = Pattern.compile(bus);
            Matcher matcher = pattern.matcher(id);
            if (matcher.matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if one of the roles match the bus roles definition.
     *
     * @param busId the bus ID.
     * @param roles the roles to check.
     * @return true if at least one of the role match, false else.
     */
    public boolean authorize(String busId, List<String> roles) throws Exception {
        LOGGER.debug("Checking authorization for bus {}", busId);
        String[] configuredRoles = this.getBusRoles(busId);
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
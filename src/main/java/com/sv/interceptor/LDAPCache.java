package com.sv.interceptor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.event.EventDirContext;
import javax.naming.event.NamespaceChangeListener;
import javax.naming.event.NamingEvent;
import javax.naming.event.NamingExceptionEvent;
import javax.naming.event.ObjectChangeListener;
import java.io.Closeable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LDAPCache implements Closeable, NamespaceChangeListener, ObjectChangeListener {

    private static final ConcurrentMap<LDAPOptions, LDAPCache> CACHES = new ConcurrentHashMap<>();

    private static Logger LOGGER = LogManager.getLogger(LDAPCache.class);

    public static void clear() {
        while (!CACHES.isEmpty()) {
            LDAPOptions options = CACHES.keySet().iterator().next();
            LDAPCache cache = CACHES.remove(options);
            if (cache != null) {
                cache.clearCache();
            }
        }
    }

    public static LDAPCache getCache(LDAPOptions options) {
        LDAPCache cache = CACHES.get(options);
        if (cache == null) {
            CACHES.putIfAbsent(options, new LDAPCache(options));
            cache = CACHES.get(options);
        }
        return cache;
    }

    private final Map<String, String[]> DnAndNamespaceMap;
    // groupDN, [groupDN1, groupDN2, ...]
    private final Map<String, List<String>> membersOfMap;
    private final LDAPOptions options;
    private DirContext context;

    public LDAPCache(LDAPOptions options) {
        this.options = options;
        DnAndNamespaceMap = new HashMap<>();
        membersOfMap = new HashMap<>();
    }

    @Override
    public synchronized void close() {
        clearCache();
        if (context != null) {
            try {
                context.close();
            } catch (NamingException e) {
                // Ignore
            } finally {
                context = null;
            }
        }
    }

    private boolean isContextAlive() {
        boolean alive = false;
        if (context != null) {
            try {
                context.getAttributes("");
                alive = true;
            } catch (Exception e) {
                // Ignore
            }
        }
        return alive;
    }

    public synchronized DirContext open() throws NamingException {
        if (isContextAlive()) {
            return context;
        }
        clearCache();
        context = new InitialDirContext(options.getEnv());

        EventDirContext eventContext = ((EventDirContext) context.lookup(""));

        final SearchControls constraints = new SearchControls();
        constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

        if (!options.getDisableCache()) {
            String filter = options.getUserFilter();
            filter = filter.replaceAll(Pattern.quote("%u"), Matcher.quoteReplacement("*"));
            filter = filter.replace("\\", "\\\\");
            eventContext.addNamingListener(options.getUserBaseDn(), filter, constraints, this);

            filter = options.getRoleFilter();
            if (filter != null) {
                filter = filter.replaceAll(Pattern.quote("%u"), Matcher.quoteReplacement("*"));
                filter = filter.replaceAll(Pattern.quote("%dn"), Matcher.quoteReplacement("*"));
                filter = filter.replaceAll(Pattern.quote("%fqdn"), Matcher.quoteReplacement("*"));
                filter = filter.replace("\\", "\\\\");
                eventContext.addNamingListener(options.getRoleBaseDn(), filter, constraints, this);
            }
        }
        return context;
    }

    public synchronized String getFirstMatchingGroup(String user, String[] expectedRoles) throws Exception {
        LOGGER.info("Check user {} with roles {}", user, expectedRoles);
        List<String> userGroups = getMembersOf(user);

        if (userGroups == null) {
            String [] userDN = getUserDnAndNamespace(user);
            if (userDN == null || userDN.length == 0) {
                return null;
            }
            userGroups = getMembersOf(user);
        }

        if (userGroups.size() == 0) {
            LOGGER.info("User {} has no group, abort", user);
            return null;
        }
        return getFirstMatchingGroup(userGroups, expectedRoles, 0);
    }

    private String getFirstMatchingGroup(List <String> groupsDNs, String[] expectedGroups, int depth) throws Exception {
        LOGGER.info("Check groups {} in depth {}", groupsDNs, depth);
        if (depth > options.getMaxDepth()) {
            LOGGER.info("Max depth reached, abort");
            return null;
        }

        if (groupsDNs.size() == 0) {
            LOGGER.info("No group to check here");
            return null;
        }

        Iterator <String> iterator = groupsDNs.iterator();
        while(iterator.hasNext()) {
            String groupDN = iterator.next();
            String groupName = getGroupName(groupDN);
            LOGGER.debug("User is member of group {}", groupName);
            if (Arrays.asList(expectedGroups).contains(groupName)) {
                LOGGER.info("Group {} matches one expected group (depth={})", groupName, depth);
                return groupName;
            }
        }
        LOGGER.info("Depth {} has no matching group, go deeper", depth);

        iterator = groupsDNs.iterator();

        List <String> nextGroupsDNs = new ArrayList <String>();

        while(iterator.hasNext()) {
            String groupDN = iterator.next();
            LOGGER.info("Check parents of group {}", groupDN);
            nextGroupsDNs.addAll(getMembersOf(groupDN));
        }
        return getFirstMatchingGroup(nextGroupsDNs, expectedGroups, depth + 1);
    }

    public synchronized List<String> getMembersOf(String ou) throws Exception {
        List<String> members = membersOfMap.get(ou);
        if (members == null || members.size() == 0) {
            LOGGER.debug("Group {} is not member of any group", ou);
        } else {
            LOGGER.debug("Group {} is member of groups {}", ou, members);
        }
        return members;
    }

    // cache User DN and membersOfMap
    public synchronized String[] getUserDnAndNamespace(String user) throws Exception {
        if (DnAndNamespaceMap.containsKey(user)) {
            LOGGER.info("Get user {} from cache", user);
            return DnAndNamespaceMap.get(user);
        }

        SearchResult response = doGetUserDnAndNamespace(user);

        if (response == null) {
            LOGGER.info("User {} not found in LDAP", user);
            return null;
        }
        String userDNNamespace = response.getNameInNamespace();
        // handle case where cn, ou, dc case doesn't match
        int indexOfUserBaseDN = userDNNamespace.toLowerCase().indexOf("," + options.getUserBaseDn().toLowerCase());
        String userDN = (indexOfUserBaseDN > 0) ? userDNNamespace.substring(0, indexOfUserBaseDN) : response.getName();

        String[] result = new String[]{userDN, userDNNamespace};

        if (!options.getDisableCache()) {
            DnAndNamespaceMap.put(user, result);
            Attributes attributes = response.getAttributes();
            Attribute memberof = attributes.get("memberof");

            List<String> groupList = new ArrayList<>();
            for (int i = 0; i < memberof.size(); i++) {
                String group = (String) memberof.get(i);

                if (group != null) {
                    LOGGER.debug("User {} is a member of group {}", user, group);
                    groupList.add(group);
                }
            }

            if (!options.getDisableCache()) {
                membersOfMap.put(user, groupList);
            }
        }

        return result;
    }

    // make the LDAP query
    protected SearchResult doGetUserDnAndNamespace(String user) throws NamingException {
        LOGGER.info("Get user {} from LDAP", user);
        DirContext context = open();

        SearchControls controls = new SearchControls();
        if (options.getUserSearchSubtree()) {
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        } else {
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        }

        String filter = options.getUserFilter();
        filter = filter.replaceAll(Pattern.quote("%u"), Matcher.quoteReplacement(user));
        filter = filter.replace("\\", "\\\\");

        LOGGER.debug("Looking for the user in LDAP with ");
        LOGGER.debug("  base DN: " + options.getUserBaseDn());
        LOGGER.debug("  filter: " + filter);

        NamingEnumeration<SearchResult> namingEnumeration = context.search(options.getUserBaseDn(), filter, controls);
        try {
            if (!namingEnumeration.hasMore()) {
                LOGGER.warn("User " + user + " not found in LDAP.");
                return null;
            }
            LOGGER.debug("Found the user DN.");
            return namingEnumeration.next();
        } finally {
            if (namingEnumeration != null) {
                try {
                    namingEnumeration.close();
                } catch (NamingException e) {
                    // Ignore
                }
            }
        }
    }

    public synchronized String getGroupName(String groupDN) throws Exception {
        if (DnAndNamespaceMap.containsKey(groupDN)) {
            LOGGER.debug("Get name of group {} from cache", groupDN);
            return DnAndNamespaceMap.get(groupDN)[0];
        }

        NamingEnumeration<SearchResult> namingEnumeration = doGetGroupName(groupDN);
        try {
            if (!namingEnumeration.hasMore()) {
                LOGGER.warn("Group " + groupDN + " not found in LDAP.");
                return null;
            }

            LOGGER.debug("Group DN {} found in LDAP.", groupDN);
            SearchResult result = namingEnumeration.next();

            List<String> membersList = new ArrayList<>();
            Attributes attributes = result.getAttributes();

            Attribute names = attributes.get("name");
            String name = null;
            if (names != null && names.size() > 0) {
                name = (String) names.get(0);
                LOGGER.debug("Group DN {} has {} as name.", groupDN, name);
                if (!options.getDisableCache()) {
                    DnAndNamespaceMap.put(groupDN, new String[] { name });
                }
            } else {
                LOGGER.debug("Group DN {} has no name, abort.", groupDN);
                return null;
            }

            Attribute members = attributes.get("memberOf");
            if (members != null) {
                for (int i = 0; i < members.size(); i++) {
                    String member = (String) members.get(i);
                    if (member != null) {
                        LOGGER.debug("{} is a member of group {}", member, groupDN);
                        membersList.add(member);
                    }
                }
            }

            if (!options.getDisableCache()) {
                membersOfMap.put(groupDN, membersList);
            }

            return name;
        } finally {
            if (namingEnumeration != null) {
                try {
                    namingEnumeration.close();
                } catch (NamingException e) {
                    // Ignore
                }
            }
        }

    }

    // make the LDAP query
    private NamingEnumeration<SearchResult> doGetGroupName(String member) throws NamingException {
        LOGGER.info("Get group {} from LDAP", member);
        DirContext context = open();

        SearchControls controls = new SearchControls();
        if (options.getRoleSearchSubtree()) {
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        } else {
            controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        }

        String filter = options.getRoleFilter();
        if (filter != null) {
            filter = filter.replaceAll(Pattern.quote("%grp"), Matcher.quoteReplacement(member));
            filter = filter.replace("\\", "\\\\");

            LOGGER.debug("Looking for the groups in LDAP with ");
            LOGGER.debug("  base DN: " + options.getRoleBaseDn());
            LOGGER.debug("  filter: " + filter);

            return context.search(options.getRoleBaseDn(), filter, controls);
        } else {
            LOGGER.debug("The member filter is null so no groups are retrieved");
            return null;
        }
    }

    @Override
    public void objectAdded(NamingEvent evt) {
        clearCache();
    }

    @Override
    public void objectRemoved(NamingEvent evt) {
        clearCache();
    }

    @Override
    public void objectRenamed(NamingEvent evt) {
        clearCache();
    }

    @Override
    public void objectChanged(NamingEvent evt) {
        clearCache();
    }

    @Override
    public void namingExceptionThrown(NamingExceptionEvent evt) {
        clearCache();
    }

    protected synchronized void clearCache() {
        LOGGER.info("Cache cleared.");
        DnAndNamespaceMap.clear();
        membersOfMap.clear();
    }
}

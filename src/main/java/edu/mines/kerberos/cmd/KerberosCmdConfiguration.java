/**
 * Copyright (C) 2011 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.mines.kerberos.cmd;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 *  KerberosCmdConfiguration
 *      Connector configuration
 */
public class KerberosCmdConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(KerberosCmdConfiguration.class);

    public static final String OBJECT_CLASS = "OBJECT_CLASS";

    //Script specific items (can make configurable below if needed)
    public static final String SCRIPT_PRINCIPAL_FLAG = "-p";
    public static final String SCRIPT_KEYTAB_FLAG = "-k";
    public static final String SCRIPT_CREATE_FLAG = "-a";
    public static final String SCRIPT_DELETE_FLAG = "-d";
    public static final String SCRIPT_LOCK_FLAG = "-f";
    public static final String SCRIPT_UNLOCK_FLAG = "-t";
    public static final String SCRIPT_CHANGE_PASSWORD_FLAG = "-c";
    public static final String SCRIPT_LIST_ALL_USERS_FLAG = "-l";
    public static final String SCRIPT_SHOW_DETAILS_FLAG = "-s";

    public static final String SCRIPT_PASSWORD_ATTRIBUTE_NAME = "user_password";
    public static final String SCRIPT_USER_NAME_ATTRIBUTE_NAME = "user_name";
    public static final String SCRIPT_USER_LOCKED_ATTRIBUTE_NAME = "user_locked";
    public static final String SCRIPT_USER_FLAGS_ATTRIBUTE_NAME = "user_flags";

    public static final String SCRIPT_LOCKED_KERBEROS_FLAG = "KRB5_KDB_DISALLOW_ALL_TIX";
    public static final String SCRIPT_SINGLE_RESULT_HEADER = "Attributes for ";

    public static final Map<Integer,String> SCRIPT_EXIT_ERROR_CODES = new HashMap<>();
    //End specific items for script

    //Configuration options
    protected static boolean shouldRedirectErrorOutput = false;

    private final ObjectClass objectClass;

    private String adminPrincipal;

    private String keytabPath;

    private String scriptCmdPath;

    private String scriptCmdType;

    private String testCmdPath ;

    private String domainToRemoveFromSearchParam;

    private String userLockedAttributeValue;

    private String userUnlockedAttributeValue;

    private String scriptErrorResponse;

    private String scriptUpdateUsernameDeleteAdd;

    private String logPasswordConfig;


    public KerberosCmdConfiguration() {
        this(ObjectClass.ACCOUNT, null);
    }

    public KerberosCmdConfiguration(final ObjectClass oc, final Map<String, Object> values) {
        if (SCRIPT_EXIT_ERROR_CODES.isEmpty()) {
            SCRIPT_EXIT_ERROR_CODES.put(0, "SUCCESS");
            SCRIPT_EXIT_ERROR_CODES.put(1, "ERROR");
            SCRIPT_EXIT_ERROR_CODES.put(200, "SPOOL_FILE_ERROR");
            SCRIPT_EXIT_ERROR_CODES.put(201, "USER_NOT_EXIST");
            SCRIPT_EXIT_ERROR_CODES.put(202, "USER_ALREADY_EXISTS");
            SCRIPT_EXIT_ERROR_CODES.put(203, "INVALID_PASSWORD");
            SCRIPT_EXIT_ERROR_CODES.put(43787527, "USER_ALREADY_EXISTS");
            SCRIPT_EXIT_ERROR_CODES.put(43787532, "USER_NOT_EXIST");
            SCRIPT_EXIT_ERROR_CODES.put(43787545, "CANNOT_REUSE_PASSWORD");
            SCRIPT_EXIT_ERROR_CODES.put(43787543, "NOT_ENOUGH_CHAR_CLASSES");
            SCRIPT_EXIT_ERROR_CODES.put(43787542, "PASSWORD_TOO_SHORT");
        }

        if (oc != null) {
            this.objectClass = oc;
        } else {
            this.objectClass = ObjectClass.ACCOUNT;
        }

        try {
            setAdminPrincipal(getSafeValue(values, "adminPrincipal", null));
            setKeytabPath(getSafeValue(values, "keytabPath", null));
            setScriptCmdPath(getSafeValue(values, "scriptCmdPath", null));
            setScriptCmdType(getSafeValue(values, "scriptCmdType", null));
            setTestCmdPath(getSafeValue(values, "testCmdPath", null));
            setRedirectErrorOutput(getSafeValue(values, "redirectErrorOutput", null));
            setDomainToRemoveFromSearchParam(getSafeValue(values, "domainToRemoveFromSearchParam", null));
            setUserLockedAttributeValue(getSafeValue(values, "userLockedAttributeValue", null));
            setUserUnlockedAttributeValue(getSafeValue(values, "userUnlockedAttributeValue", null));
            setScriptErrorResponse(getSafeValue(values, "scriptErrorResponse", null));
            setScriptUpdateUsernameDeleteAdd(getSafeValue(values, "scriptUpdateUsernameDeleteAdd", null));
            setLogPasswordConfig(getSafeValue(values, logPasswordConfig, "false"));

        } catch (Exception e) {
            LOG.ok("Error setting configuration values! " + e.getMessage());
        }
    }

    //Getters and Setters
    @ConfigurationProperty(displayMessageKey = "kerberosCmd.adminPrincipal.display",
            helpMessageKey = "kerberosCmd.adminPrincipal.help", order = 3)
    public String getAdminPrincipal() {
        return trimValue(adminPrincipal);
    }

    public void setAdminPrincipal(final String adminPrincipal) {
        this.adminPrincipal = adminPrincipal;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.keytabPath.display",
            helpMessageKey = "kerberosCmd.keytabPath.help", order = 4)
    public String getKeytabPath() {
        return trimValue(keytabPath);
    }

    public void setKeytabPath(final String keytabPath) {
        this.keytabPath = keytabPath;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.scriptCmdPath.display",
            helpMessageKey = "kerberosCmd.scriptCmdPath.help", order = 2)
    public String getScriptCmdPath() {
        return trimValue(scriptCmdPath);
    }

    public void setScriptCmdPath(final String scriptCmdPath) {
        this.scriptCmdPath = scriptCmdPath;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.scriptCmdType.display",
            helpMessageKey = "kerberosCmd.scriptCmdType.help", order = 1)
    public String getScriptCmdType() {
        return trimValue(scriptCmdType);
    }

    public void setScriptCmdType(final String scriptCmdType) {
        this.scriptCmdType = scriptCmdType;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.testCmdPath.display",
            helpMessageKey = "kerberosCmd.testCmdPath.help", order = 7)
    public String getTestCmdPath() {
        return trimValue(testCmdPath);
    }

    public void setTestCmdPath(final String testCmdPath) {
        this.testCmdPath = testCmdPath;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.redirectErrorOutput.display",
            helpMessageKey = "kerberosCmd.redirectErrorOutput.help", order = 5)
    public String getRedirectErrorOutput() {
        return String.valueOf(shouldRedirectErrorOutput);
    }

    public void setRedirectErrorOutput(final String redirectErrorOutput) {
        shouldRedirectErrorOutput = Boolean.parseBoolean(trimValue(redirectErrorOutput));
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.domainToRemoveFromSearchParam.display",
            helpMessageKey = "kerberosCmd.domainToRemoveFromSearchParam.help", order = 6)
    public String getDomainToRemoveFromSearchParam() {
        return trimValue(domainToRemoveFromSearchParam);
    }

    public void setDomainToRemoveFromSearchParam(final String domainToRemoveFromSearchParam) {
        this.domainToRemoveFromSearchParam = domainToRemoveFromSearchParam;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.userLockedAttributeValue.display",
            helpMessageKey = "kerberosCmd.userLockedAttributeValue.help", order = 6)
    public String getUserLockedAttributeValue() {
        return trimValue(userLockedAttributeValue);
    }

    public void setUserLockedAttributeValue(final String userLockedAttributeValue) {
        this.userLockedAttributeValue = userLockedAttributeValue;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.userUnlockedAttributeValue.display",
            helpMessageKey = "kerberosCmd.userUnlockedAttributeValue.help", order = 6)
    public String getUserUnlockedAttributeValue() {
        return trimValue(userUnlockedAttributeValue);
    }

    public void setUserUnlockedAttributeValue(final String userUnlockedAttributeValue) {
        this.userUnlockedAttributeValue = userUnlockedAttributeValue;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.scriptErrorValue.display",
            helpMessageKey = "kerberosCmd.scriptErrorValue.help", order = 7)
    public String getScriptErrorResponse() {
        return trimValue(scriptErrorResponse);
    }

    public void setScriptErrorResponse(final String scriptErrorResponse) {
        this.scriptErrorResponse = scriptErrorResponse;
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.scriptUpdateUsernameDeleteAdd.display",
            helpMessageKey = "kerberosCmd.scriptUpdateUsernameDeleteAdd.help", order = 8)
    public String getScriptUpdateUsernameDeleteAdd() {
        return trimValue(scriptUpdateUsernameDeleteAdd);
    }

    public void setScriptUpdateUsernameDeleteAdd(final String scriptUpdateUsernameDeleteAdd) {
        this.scriptUpdateUsernameDeleteAdd = scriptUpdateUsernameDeleteAdd;
    }

    public boolean shouldScriptUpdateUsername() {
        return convertStringToBoolean(getScriptUpdateUsernameDeleteAdd());
    }

    @ConfigurationProperty(displayMessageKey = "kerberosCmd.logPasswordConfig.display",
            helpMessageKey = "kerberosCmd.logPasswordConfig.help", order = 8)
    public String getLogPasswordConfig() {
        return trimValue(logPasswordConfig);
    }

    public void setLogPasswordConfig(final String logPasswordConfig) {
        this.logPasswordConfig = logPasswordConfig;
    }

    public boolean shouldLogPassword() {
        return convertStringToBoolean(getLogPasswordConfig());
    }

    public ObjectClass getObjectClass() {
        return objectClass;
    }
    //end getters and setters

    @Override
    public void validate() {
        if (StringUtil.isBlank(scriptCmdPath)) {
            throw new ConfigurationException("Script path must not be blank!");
        }
        if (StringUtil.isBlank(adminPrincipal)) {
            throw new ConfigurationException("Admin Principal must not be blank!");
        }
        if (StringUtil.isBlank(keytabPath)) {
            throw new ConfigurationException("Keytab path must not be blank!");
        }
    }

    private <T> T getSafeValue(Map<String, Object> map, String key, T defValue) {
            return (T) getSafeValue(map, key, defValue, (Class) String.class);
    }

    private <T> T getSafeValue(Map<String, Object> map, String key, T defValue, Class<T> type) {
        if (map == null) {
            return defValue;
        }

        Object value = map.get(key);
        if (value == null) {
            return defValue;
        }

        String strValue = value.toString();
        if (String.class.equals(type)) {
            return (T) strValue;
        } else if (Integer.class.equals(type)) {
            return (T) Integer.valueOf(strValue);
        } else if (Boolean.class.equals(type)) {
            return (T) Boolean.valueOf(strValue);
        } else if (File.class.equals(type)) {
            return (T) new File(strValue);
        }

        return defValue;
    }

    private String trimValue(final String stringToTrim) {
        if (stringToTrim != null) {
            return stringToTrim.trim();
        }

        return null;
    }

    private boolean convertStringToBoolean(final String stringToParse) {
        try {
            return Boolean.parseBoolean(stringToParse);
        } catch (Exception e) {
            return false;
        }
    }
}

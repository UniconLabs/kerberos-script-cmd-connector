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
package edu.mines.kerberos.cmd.methods;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import edu.mines.kerberos.cmd.KerberosCmdConnection;
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import edu.mines.kerberos.cmd.KerberosCmdConnector;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;


/**
 * KerberosCmdExec
 *  Provides common methods and abstraction
 *   around the Script CMD execution process
 */
public abstract class KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdExec.class);

    protected final ObjectClass oc;
    
    protected final KerberosCmdConfiguration kerberosCmdConfiguration;

    private String scriptType;


    public KerberosCmdExec(final ObjectClass oc, final KerberosCmdConfiguration kerberosCmdConfiguration) {
        this.oc = oc;
        this.kerberosCmdConfiguration = kerberosCmdConfiguration;
        setScriptType();
    }

    protected Process execScriptCmd(final String scriptToExecute, final List<String> paramsAndArgs,
                                    final List<Pair<String, String>> env) throws ConnectorException {

        final List<String> command = new ArrayList<>();
        LOG.ok("Parameters and arguments passed: " + KerberosCmdConnector.logSanitizePassword(paramsAndArgs, env));

        if (scriptType != null) {
            command.add(scriptType);
        }
        command.add(scriptToExecute);
        command.add(KerberosCmdConfiguration.SCRIPT_PRINCIPAL_FLAG);
        command.add(kerberosCmdConfiguration.getAdminPrincipal());
        command.add(KerberosCmdConfiguration.SCRIPT_KEYTAB_FLAG);
        command.add(kerberosCmdConfiguration.getKeytabPath());

        command.addAll(paramsAndArgs);
        LOG.ok("Built Script Command: " + KerberosCmdConnector.logSanitizePassword(command, env));

        try {
            return KerberosCmdConnection.openConnection().executeScriptCmd(command, env);

        } catch (Exception e) {
            LOG.error(e, "Error executing script: " + command);
            throw new ConnectorException(e);
        }
    }

    //Not used
    protected List<Pair<String, String>> createEnv(
            final Set<Attribute> attrs,
            final KerberosCmdConfiguration kerberosCmdConfiguration) {
        return createEnv(attrs, null, kerberosCmdConfiguration);
    }

    //Not used at the moment
    protected List<Pair<String, String>> createEnv(
            final Set<Attribute> attrs,
            final Uid uid,
            final KerberosCmdConfiguration kerberosCmdConfiguration) {
        final List<Pair<String, String>> env = new ArrayList<>();

        LOG.ok("Creating environment with:");
        if (oc != null) {
            LOG.ok(KerberosCmdConfiguration.OBJECT_CLASS + ": {0}", oc.getObjectClassValue());
            env.add(new Pair<>(KerberosCmdConfiguration.OBJECT_CLASS, oc.getObjectClassValue()));
        }

        for (Attribute attr : attrs) {
            if (attr.getValue() != null && !attr.getValue().isEmpty()) {
                LOG.ok("Environment variable {0}: {1}", attr.getName(), attr.getValue().get(0));

                if (OperationalAttributes.PASSWORD_NAME.equals(attr.getName())) {
                    GuardedString gpasswd = AttributeUtil.getPasswordValue(attrs);
                    if (gpasswd != null) {
                        env.add(new Pair<>(OperationalAttributes.PASSWORD_NAME, SecurityUtil.decrypt(gpasswd)));
                    }
                } else {
                    env.add(new Pair<>(attr.getName(), StringUtil.join(attr.getValue().toArray(), ',')));
                }
            }
        }
        
        if (uid != null && AttributeUtil.find(Uid.NAME, attrs) == null) {
            LOG.ok("Environment variable {0}: {1}", Uid.NAME, formatUsername(uid.getUidValue()));
            env.add(new Pair<>(Uid.NAME, formatUsername(uid.getUidValue())));
        }

        return env;

    }

    protected Pair<Boolean,String> scriptExecuteSuccess(final Process proc) {
        int statusCode = 1;
        final StringBuilder statusMessage = new StringBuilder();
        final ExecutorService threadPool = Executors.newSingleThreadExecutor();

        try {
            final ReadProcessOutput stdOutputStreamReader = new ReadProcessOutput(proc.getInputStream());
            final Future<List<String>> procStdOutput = threadPool.submit(stdOutputStreamReader);
            final ReadProcessOutput errorOutputStreamReader = new ReadProcessOutput(proc.getErrorStream());
            final Future<List<String>> procErrorOutput = threadPool.submit(errorOutputStreamReader);

            proc.waitFor();

            try {
                final List<String> errorOutput = procErrorOutput.get(5, TimeUnit.SECONDS);
                if (!errorOutput.isEmpty()) {
                    LOG.error("Found error in script: " + errorOutput);
                    statusMessage.append(errorOutput).append(" ");
                }
            } catch (Exception ioe) {
                //swallow
            }

            try {
                final List<String> stdOutput = procStdOutput.get(5, TimeUnit.SECONDS);

                if (Boolean.parseBoolean(kerberosCmdConfiguration.getRedirectErrorOutput())) {
                    for (final String it : stdOutput) {
                        if (it.contains(kerberosCmdConfiguration.getScriptErrorResponse())) {
                            LOG.error("Found error in script: " + it);
                            statusMessage.append(it).append(" ");
                        }
                    }
                }
            } catch (Exception ioe2) {
                //swallow
            }

            statusCode = proc.exitValue();
            KerberosCmdConnector.logScriptStatus(statusCode);

        } catch (Exception e) {
            LOG.error(e, "Error waiting for process termination or reading output!");
            statusMessage.append(e.getMessage()).append(" ");
            statusCode = 1;
        } finally {
            threadPool.shutdown();
        }

        if (statusCode == 0 && statusMessage.length() > 0) {
            statusCode = 1; //let's force the error code since perhaps the script isn't reporting exit status
        }

        return new Pair(statusCode == 0, statusMessage.toString());
    }

    protected GuardedString getPasswordFromAttributes(final Set<Attribute> attributes) {
        if (!attributes.isEmpty()) {
            Attribute passwd = AttributeUtil.find(KerberosCmdConfiguration.SCRIPT_PASSWORD_ATTRIBUTE_NAME, attributes); //try configured password value

            if (passwd == null) {
                passwd = AttributeUtil.find(OperationalAttributes.PASSWORD_NAME, attributes); //try standard password attribute
            }

            if (passwd == null) {
                throw new IllegalArgumentException("No Password provided in the attributes");
            } else {
                return AttributeUtil.getGuardedStringValue(passwd);
            }
        }

        return null;
    }

    protected String getNameFromAttributes(final Set<Attribute> attributes) {
        Attribute usernameRaw = AttributeUtil.getNameFromAttributes(attributes); //try standard name param

        if (usernameRaw == null) {
            usernameRaw = AttributeUtil.find(KerberosCmdConfiguration.SCRIPT_USER_NAME_ATTRIBUTE_NAME, attributes); //try set username param
        }

        if (usernameRaw != null && !usernameRaw.getValue().isEmpty()) {
            return AttributeUtil.getAsStringValue(usernameRaw).trim();
        }

        return null;
    }

    protected int isUserLocked(final Set<Attribute> attributes) {
        Attribute lockedRawAttr = AttributeUtil.find(KerberosCmdConfiguration.SCRIPT_USER_LOCKED_ATTRIBUTE_NAME, attributes); //try configured value
        if (lockedRawAttr == null) {
            lockedRawAttr = AttributeUtil.find(OperationalAttributes.LOCK_OUT_NAME, attributes); //try standard lock out value
        }

        if (lockedRawAttr != null && !lockedRawAttr.getValue().isEmpty()) {
            final String lockedValue = StringUtil.join(lockedRawAttr.getValue().toArray(), ',');
            if (lockedValue.equalsIgnoreCase(kerberosCmdConfiguration.getUserLockedAttributeValue())) {
                return 1;
            } else if (lockedValue.equalsIgnoreCase(kerberosCmdConfiguration.getUserUnlockedAttributeValue())) {
                return 0;
            }
        }

        return -1;
    }

    protected String formatUsername(final String rawUsernameParam) {
        if (StringUtil.isNotBlank(kerberosCmdConfiguration.getDomainToRemoveFromSearchParam())) {
            return rawUsernameParam.replaceAll(kerberosCmdConfiguration.getDomainToRemoveFromSearchParam(), "").trim();
        }

        return rawUsernameParam.trim();
    }

    private void setScriptType() {
        if (kerberosCmdConfiguration != null && StringUtil.isNotBlank(kerberosCmdConfiguration.getScriptCmdType())) {
            this.scriptType = kerberosCmdConfiguration.getScriptCmdType();
        }
    }

    private static class ReadProcessOutput implements Callable<List<String>> {

        private final InputStream input;

        public ReadProcessOutput(final InputStream processInputStream) {
            this.input = processInputStream;
        }

        @Override
        public final List<String> call() {
            return new BufferedReader(new InputStreamReader(input)).lines().collect(Collectors.toList());
        }
    }
}

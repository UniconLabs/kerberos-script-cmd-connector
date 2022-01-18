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

import java.util.*;

import edu.mines.kerberos.cmd.KerberosCmdConnection;
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import edu.mines.kerberos.cmd.KerberosCmdConnector;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;


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

        LOG.ok("Paramaters and arguments passed: " + paramsAndArgs.toString());
        if (scriptType != null) {
            command.add(scriptType);
        }
        command.add(scriptToExecute);
        command.add(KerberosCmdConfiguration.SCRIPT_PRINCIPAL_FLAG);
        command.add(kerberosCmdConfiguration.getAdminPrincipal());
        command.add(KerberosCmdConfiguration.SCRIPT_KEYTAB_FLAG);
        command.add(kerberosCmdConfiguration.getKeytabPath());

        command.addAll(paramsAndArgs);
        LOG.ok("Script Command: " + command);

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

    protected boolean scriptExecuteSuccess(final Process proc) {
        int statusCode = 1;

        try {
            proc.waitFor();

            statusCode = proc.exitValue();
            KerberosCmdConnector.logScriptStatus(statusCode);

        } catch (InterruptedException e) {
            LOG.error(e, "Error waiting for termination");
        }

        return statusCode == 0;
    }

    protected GuardedString getPasswordFromAttributes(final Attribute passwordAttribute) {
        if (passwordAttribute != null) {
            return AttributeUtil.getGuardedStringValue(passwordAttribute);
        }

        return null;
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
}

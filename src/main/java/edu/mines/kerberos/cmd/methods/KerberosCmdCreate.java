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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;


/**
 *  KerberosCmdCreate
 *    Provides the Create functionality.
 */
public class KerberosCmdCreate extends KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdCreate.class);

    private final Set<Attribute> attrs;

    public KerberosCmdCreate(final ObjectClass oc, final KerberosCmdConfiguration kerberosCmdConfiguration, final Set<Attribute> attrs) {
        super(oc, kerberosCmdConfiguration);

        this.attrs = attrs;
    }

    public Uid execCreateCmd() throws ConnectorException, IllegalArgumentException {
        final String name = getNameFromAttributes(attrs);
        if (StringUtil.isBlank(name)) {
            throw new IllegalArgumentException("No Name provided in the attributes");
        }

        final GuardedString gpasswd = getPasswordFromAttributes(attrs);
        if (gpasswd == null) {
            throw new IllegalArgumentException("No Password provided in the attributes");
        }
        LOG.info("Executing creation for {0}", name);

        Pair<Boolean, String> status = scriptExecuteSuccess(execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), createAddUserParameters(name, gpasswd), null));

        if (!status.getKey()) {
            LOG.error("Kerberos add user didn't return success for [{0}]!", formatUsername(name));
            throw new ConnectorException(status.getValue());
        }

        if (isUserLocked(attrs) == 1) {
            final List<String> updateLockeStatusParms = new ArrayList<>();
            updateLockeStatusParms.add(KerberosCmdConfiguration.SCRIPT_LOCK_FLAG);
            updateLockeStatusParms.add(formatUsername(name));

            status = scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updateLockeStatusParms, null)));

            if (!status.getKey()) {
                LOG.error("Kerberos add freeze didn't return success for [{0}]!", formatUsername(name));
                //don't throw an error TODO we can if needed
            }
        }

        return new Uid(name);
    }

    private List<String> createAddUserParameters(final String name, final GuardedString password) {
        LOG.ok("Creating parameters for addition with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}", name);

        final List<String> addUserParams = new ArrayList<>();
        addUserParams.add(KerberosCmdConfiguration.SCRIPT_CREATE_FLAG);
        addUserParams.add(formatUsername(name));
        addUserParams.add(SecurityUtil.decrypt(password));

        return addUserParams;
    }
}

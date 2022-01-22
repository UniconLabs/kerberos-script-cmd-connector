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
 * KerberosCmdUpdate
 *   Provides the Update functionality
 */
public class KerberosCmdUpdate extends KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdUpdate.class);

    private final Uid uid;

    private final Set<Attribute> attrs;

    public KerberosCmdUpdate(final ObjectClass oc,
                             final KerberosCmdConfiguration kerberosCmdConfiguration,
                             final Uid uid, final Set<Attribute> attrs) {
        super(oc, kerberosCmdConfiguration);

        this.uid = uid;
        this.attrs = attrs;
    }

    public Uid execUpdateCmd() throws ConnectorException {
        LOG.info("Executing the update for {0}", uid);

        Pair<Boolean,String> status = updateUserName();
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update username didn't return success for " + formatUsername(uid.getUidValue()) + " with " + status.getValue());

        }

        status = updateUserPassword();
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update password didn't return success for " + formatUsername(uid.getUidValue()) + " with " + status.getValue());

        }

        status = updateUserLockStatus();
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update thaw or freeze didn't return success for " + formatUsername(uid.getUidValue()) + " with " + status.getValue());
        }

        return uid;
    }

    private Pair<Boolean,String> updateUserName() {
        LOG.ok("Creating parameters for username update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formatUsername(uid.getUidValue()));

        final String username = getNameFromAttributes(attrs);
        if (StringUtil.isNotBlank(username) &&
                kerberosCmdConfiguration.shouldScriptUpdateUsername() &&
                !uid.getUidValue().equals(username)) {
            new KerberosCmdDelete(oc, kerberosCmdConfiguration, uid).execDeleteCmd(); //delete user since the script doesn't allow updates?
            new KerberosCmdCreate(oc, kerberosCmdConfiguration, attrs).execCreateCmd(); //add user with new username
        }

        return new Pair(Boolean.TRUE, "");
    }

    private Pair<Boolean,String> updateUserPassword() {
        LOG.ok("Creating parameters for password update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formatUsername(uid.getUidValue()));

        final List<String> updatePasswordParameters = new ArrayList<>();
        final GuardedString gpasswd = getPasswordFromAttributes(attrs);
        if (gpasswd != null) {
            updatePasswordParameters.add(KerberosCmdConfiguration.SCRIPT_CHANGE_PASSWORD_FLAG);
            updatePasswordParameters.add(formatUsername(uid.getUidValue()));
            updatePasswordParameters.add(SecurityUtil.decrypt(gpasswd));
        }

        if (!updatePasswordParameters.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updatePasswordParameters, null)));
        } else {
            return new Pair(Boolean.TRUE, "");
        }
    }

    private Pair<Boolean,String> updateUserLockStatus() {
        LOG.ok("Creating parameters for freeze/thaw update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formatUsername(uid.getUidValue()));
        final List<String> updateThawFreezeParameters = new ArrayList<>();

        final int userLocked = isUserLocked(attrs);
        if (userLocked == 1) {
            updateThawFreezeParameters.add(KerberosCmdConfiguration.SCRIPT_LOCK_FLAG);
            updateThawFreezeParameters.add(formatUsername(uid.getUidValue()));

        } else if (userLocked == 0) {
            updateThawFreezeParameters.add(KerberosCmdConfiguration.SCRIPT_UNLOCK_FLAG);
            updateThawFreezeParameters.add(formatUsername(uid.getUidValue()));

        } else {
            //TODO confirm if unknown or not set do nothing for locked/thaw/freeze
        }

        if (!updateThawFreezeParameters.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updateThawFreezeParameters, null)));
        } else {
            return new Pair(Boolean.TRUE, "");
        }
    }
}

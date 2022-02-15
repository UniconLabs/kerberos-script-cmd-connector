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
        final Uid formattedUid = createFormattedUsernameUid(uid.getUidValue());
        Pair<Boolean,String> status;
        LOG.info("Executing the update for {0}", formattedUid);

        status = updateUserPassword(formattedUid);
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update password didn't return success for " + formattedUid.getUidValue() + " with " + status.getValue());
        }

        status = updateUserLockStatus(formattedUid);
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update thaw or freeze didn't return success for " + formattedUid.getUidValue() + " with " + status.getValue());
        }

        status = updateUserName(formattedUid);
        if (!status.getKey()) {
            throw new ConnectorException("Kerberos update username didn't return success for " + formattedUid.getUidValue() + " with " + status.getValue());

        }

        return uid;
    }

    private Pair<Boolean,String> updateUserPassword(final Uid formattedUid) {
        LOG.ok("Creating parameters for password update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formattedUid.getUidValue());

        final List<String> updatePasswordParameters = new ArrayList<>();
        final GuardedString gpasswd = getPasswordFromAttributes(attrs);
        if (gpasswd != null) {
            updatePasswordParameters.add(KerberosCmdConfiguration.SCRIPT_CHANGE_PASSWORD_FLAG);
            setUsernameAndPassword(formattedUid.getUidValue(), gpasswd, updatePasswordParameters);
        }

        if (!updatePasswordParameters.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updatePasswordParameters, null)));
        } else {
            return new Pair(Boolean.TRUE, "");
        }
    }

    private Pair<Boolean,String> updateUserLockStatus(final Uid formattedUid) {
        LOG.ok("Creating parameters for freeze/thaw update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formattedUid.getUidValue());
        final List<String> updateThawFreezeParameters = new ArrayList<>();

        final int userLocked = isUserLocked(attrs);
        if (userLocked == 1) {
            updateThawFreezeParameters.add(KerberosCmdConfiguration.SCRIPT_LOCK_FLAG);
            updateThawFreezeParameters.add(formattedUid.getUidValue());

        } else if (userLocked == 0) {
            updateThawFreezeParameters.add(KerberosCmdConfiguration.SCRIPT_UNLOCK_FLAG);
            updateThawFreezeParameters.add(formattedUid.getUidValue());

        } else {
            //TODO confirm if unknown or not set do nothing for locked/thaw/freeze
        }

        if (!updateThawFreezeParameters.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updateThawFreezeParameters, null)));
        } else {
            return new Pair(Boolean.TRUE, "");
        }
    }

    private Pair<Boolean,String> updateUserName(final Uid formattedUid) {
        LOG.ok("Creating parameters for username update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formattedUid.getUidValue());

        final String username = getNameFromAttributes(attrs);
        if (StringUtil.isNotBlank(username) &&
                kerberosCmdConfiguration.shouldScriptUpdateUsername() &&
                !formattedUid.getUidValue().equals(username)) {

            final List<String> updateUsernameParameters = new ArrayList<>();
            updateUsernameParameters.add(KerberosCmdConfiguration.SCRIPT_CHANGE_USERNAME_FLAG);
            updateUsernameParameters.add(formattedUid.getUidValue());
            updateUsernameParameters.add(formatUsername(username));

            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updateUsernameParameters, null)));
        }

        return new Pair(Boolean.TRUE, "");
    }
}

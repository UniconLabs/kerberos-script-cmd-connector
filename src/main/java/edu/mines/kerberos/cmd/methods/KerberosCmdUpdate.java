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
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
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

    public Uid execUpdateCmd() {
        LOG.info("Executing the update for {0}", uid);
        boolean status = false;

        status = updateUserPassword();
        if (!status) {
            LOG.error("Kerberos update password didn't return success for [{0}]!", uid.getUidValue());
        }

        status = updateUserLockStatus();
        if (!status) {
            LOG.error("Kerberos update thaw or freeze didn't return success for [{0}]!", uid.getUidValue());
        }

        return uid;
    }

    private boolean updateUserPassword() {
        LOG.ok("Creating parameters for password update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), uid.getUidValue());

        final List<String> updatePasswordCommand = new ArrayList<>();
        final GuardedString gpasswd = getPasswordFromAttributes(AttributeUtil.find(KerberosCmdConfiguration.SCRIPT_PASSWORD_ATTRIBUTE_NAME, attrs));
        if (gpasswd != null) {
            updatePasswordCommand.add(KerberosCmdConfiguration.SCRIPT_CHANGE_PASSWORD_FLAG);
            updatePasswordCommand.add(uid.getUidValue());
            updatePasswordCommand.add(SecurityUtil.decrypt(gpasswd));
        }

        if (!updatePasswordCommand.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updatePasswordCommand, null)));
        } else {
            return true;
        }
    }

    private boolean updateUserLockStatus() {
        LOG.ok("Creating parameters for freeze/thaw update with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), uid.getUidValue());

        final List<String> updateThawFreezeCommand = new ArrayList<>();
        final Attribute locked = AttributeUtil.find("user_locked", attrs);

        if (locked != null && !locked.getValue().isEmpty()) {
            final String lockValue = StringUtil.join(locked.getValue().toArray(), ',');

            if (lockValue.equalsIgnoreCase("locked")) {
                updateThawFreezeCommand.add(KerberosCmdConfiguration.SCRIPT_LOCK_FLAG);
                updateThawFreezeCommand.add(uid.getUidValue());
            }

            if (lockValue.equalsIgnoreCase("unlocked")) {
                updateThawFreezeCommand.add(KerberosCmdConfiguration.SCRIPT_UNLOCK_FLAG);
                updateThawFreezeCommand.add(uid.getUidValue());
            }

            //TODO confirm if unknown or not set do nothing for locked/thaw/freeze
        }

        if (!updateThawFreezeCommand.isEmpty()) {
            return scriptExecuteSuccess((execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), updateThawFreezeCommand, null)));
        } else {
            return true;
        }
    }
}

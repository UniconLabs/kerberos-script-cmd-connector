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
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;


/**
 *  KerberosCmdDelete
 *     Provides the Delete functionality
 */
public class KerberosCmdDelete extends KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdDelete.class);

    private final Uid uid;

    public KerberosCmdDelete(final ObjectClass oc, final KerberosCmdConfiguration kerberosCmdConfiguration, final Uid uid) {
        super(oc, kerberosCmdConfiguration);

        this.uid = uid;
    }

    public void execDeleteCmd() {
        LOG.info("Executing deletion for {0}", uid);

        scriptExecuteSuccess(execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), createDeleteUserParameters(), null));
    }

    private List<String> createDeleteUserParameters() {
        LOG.ok("Creating parameters for deletion with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}: {1}", uid.getName(), formatUsername(uid.getUidValue()));

        final List<String> deleteUserParams = new ArrayList<>();
        deleteUserParams.add(KerberosCmdConfiguration.SCRIPT_DELETE_FLAG);
        deleteUserParams.add(formatUsername(uid.getUidValue()));

        return deleteUserParams;
    }
}

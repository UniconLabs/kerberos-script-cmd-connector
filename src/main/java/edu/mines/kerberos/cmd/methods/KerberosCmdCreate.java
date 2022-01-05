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

    public Uid execCreateCmd() {
        final Name name = AttributeUtil.getNameFromAttributes(attrs);
        if (name == null || StringUtil.isBlank(name.getNameValue())) {
            throw new IllegalArgumentException("No Name provided in the attributes");
        }

        final GuardedString gpasswd = getPasswordFromAttributes(AttributeUtil.find(KerberosCmdConfiguration.SCRIPT_PASSWORD_ATTRIBUTE_NAME, attrs));
        if (gpasswd == null) {
            throw new IllegalArgumentException("No Password provided in the attributes");
        }
        LOG.info("Executing creation for {0}", name.getNameValue());

       scriptExecuteSuccess(execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), createAddUserParameters(name, gpasswd), null));

        return new Uid(name.getNameValue());
    }

    private List<String> createAddUserParameters(final Name name, final GuardedString password) {
        LOG.ok("Creating parameters for addition with: ");
        LOG.ok("ObjectClass: {0}", oc.getObjectClassValue());
        LOG.ok("User {0}", name.getNameValue());

        final List<String> addUserParams = new ArrayList<>();
        addUserParams.add(KerberosCmdConfiguration.SCRIPT_CREATE_FLAG);
        addUserParams.add(formatUsername(name.getNameValue()));
        addUserParams.add(SecurityUtil.decrypt(password));

        return addUserParams;
    }
}

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
import java.util.Collections;
import java.util.List;
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.Attribute;


public class KerberosCmdTest extends KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdTest.class);

    public KerberosCmdTest(final KerberosCmdConfiguration kerberosCmdConfiguration) {
        super(null, kerberosCmdConfiguration);
    }

    public final void test() throws ConfigurationException  {
        LOG.info("Executing test on {0}", kerberosCmdConfiguration.getTestCmdPath());
        final List<String> testParameters = new ArrayList<>(); //TODO add any needed test parameters here

        boolean success = scriptExecuteSuccess(execScriptCmd(kerberosCmdConfiguration.getTestCmdPath(),
                testParameters,
                createEnv(Collections.<Attribute>emptySet(), kerberosCmdConfiguration)));

        if (!success) {
            throw new ConfigurationException("Kerberos Script process did not return a successful code!");
        }
        LOG.ok("Test completed successfully!");
    }
}

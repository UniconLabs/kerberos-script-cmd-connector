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

import java.io.IOException;
import java.util.List;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.logging.Log;

/**
 * KerberosCmdConnection
 *   Provides abstraction around running the script using process builder.
 */
public class KerberosCmdConnection {

    private static final Log LOG = Log.getLog(KerberosCmdConnection.class);

    private static KerberosCmdConnection kerberosCmdConnection = null;

    public static KerberosCmdConnection openConnection() {
        if (kerberosCmdConnection == null) {
            kerberosCmdConnection = new KerberosCmdConnection();
        }
        return kerberosCmdConnection;
    }

    private KerberosCmdConnection() {
    }

    public Process executeScriptCmd(final List<String> command, final List<Pair<String, String>> env) throws IOException {
        LOG.info("KerberosScript executing script {0} {1}", command, env);

        final ProcessBuilder builder = new ProcessBuilder(command); //script path and arguments are in the command
        builder.redirectErrorStream(KerberosCmdConfiguration.shouldRedirectErrorOutput);

        if (env != null) {
            for (Pair<String, String> entry : env) {
                builder.environment().put(entry.first, entry.second); //this sets up environment variables, this is how the traditional CMD connector passed attributes to the CMD/Script
            }
        }

        final Process proc = builder.start(); //executes the process
        proc.getOutputStream().close();
        LOG.ok("KerberosScript script execution complete!");
        return proc;
    }
}

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
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import edu.mines.kerberos.cmd.KerberosCmdConfiguration;
import edu.mines.kerberos.cmd.search.Operand;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.*;


/**
 *  KerberosCmdExecuteQuery
 *    Provides the Search operation
 */
public class KerberosCmdExecuteQuery extends KerberosCmdExec {

    private static final Log LOG = Log.getLog(KerberosCmdExecuteQuery.class);

    private final Operand filter;

    private final ResultsHandler resultsHandler;

    public KerberosCmdExecuteQuery(final ObjectClass oc, final KerberosCmdConfiguration kerberosCmdConfiguration, final Operand filter,
                                   final ResultsHandler rh) {
        super(oc, kerberosCmdConfiguration);

        this.filter = filter;
        this.resultsHandler = rh;
    }

    public void execQuery() throws ConnectorIOException {
        final Process proc;

        proc = execScriptCmd(kerberosCmdConfiguration.getScriptCmdPath(), createSearchParameters(), null);
        readSearchOutput(proc);
    }

    private List<String> createSearchParameters() {
        final List<String> createSearchParams = new ArrayList<>();

        if (filter != null) {
            LOG.ok("Search with filter {0} ...", filter);
            LOG.ok("Creating parameters for search with: ");
            LOG.ok(KerberosCmdConfiguration.OBJECT_CLASS + ": {0}", oc.getObjectClassValue());
            LOG.ok("Query filter {0}= {1}", filter.getAttributeName(), filter.getAttributeValue());
            createSearchParams.add(KerberosCmdConfiguration.SCRIPT_SHOW_DETAILS_FLAG);
            createSearchParams.add(formatUsername(filter.getAttributeValue()));

        } else {
            LOG.ok("Full search (no filter) ...");
            createSearchParams.add(KerberosCmdConfiguration.SCRIPT_LIST_ALL_USERS_FLAG);
            createSearchParams.add(KerberosCmdConfiguration.SCRIPT_SHOW_DETAILS_FLAG);
        }

        return createSearchParams;
    }

    //TODO This is hard-coded to the Kerberos perl script to ignore words in front of single result as well add domain to username as well as ignore non-used values
    private ConnectorObject processSingleResult(final String searchScriptOutput) throws ConnectorException {

        if (StringUtil.isNotBlank(searchScriptOutput) &&
                searchScriptOutput.contains(KerberosCmdConfiguration.SCRIPT_SINGLE_RESULT_HEADER)) {

            final List<String> singleSearchRawResult =
                    new ArrayList<>(List.of(searchScriptOutput.replace(KerberosCmdConfiguration.SCRIPT_SINGLE_RESULT_HEADER, "")
                            .replace(System.lineSeparator(), "").trim().split("\\s+")));

                final StringBuilder singleSearchCompiledResult = new StringBuilder(singleSearchRawResult.get(0) +
                        kerberosCmdConfiguration.getDomainToRemoveFromSearchParam()); //For consistency adds back domain to search result username
            singleSearchRawResult.remove(0); //removes username grabbed above
            singleSearchRawResult.remove(0); //removes the hex value (value right after username)

                singleSearchRawResult.forEach(it -> {
                    singleSearchCompiledResult.append(" ").append(it); //adds flags
                });

                return processSearchResult(singleSearchCompiledResult.toString().trim());
        }

        return processSearchResult(searchScriptOutput);
    }

    private ConnectorObject processSearchResult(final String searchScriptOutput) throws ConnectorException, IllegalStateException {
        if (searchScriptOutput == null || searchScriptOutput.isEmpty()) {
            throw new ConnectorException("No search results found!");
        }

        final Properties attrs = StringUtil.toProperties(searchScriptOutput);

        final ConnectorObjectBuilder bld = new ConnectorObjectBuilder();
        for (final Map.Entry<Object, Object> attr : attrs.entrySet()) {
            final String username = attr.getKey().toString();
            final String userdata = attr.getValue().toString();
            boolean isUserLocked = false;

            if (StringUtil.isNotBlank(username)) {
                bld.setName(username);
                bld.setUid(username);
                bld.addAttribute(KerberosCmdConfiguration.SCRIPT_USER_NAME_ATTRIBUTE_NAME, username);

                if (StringUtil.isNotBlank(userdata)) {
                    bld.addAttribute(KerberosCmdConfiguration.SCRIPT_USER_FLAGS_ATTRIBUTE_NAME, userdata);

                    if (userdata.contains(KerberosCmdConfiguration.SCRIPT_LOCKED_KERBEROS_FLAG)) {
                        isUserLocked = true;
                    }
                }

                bld.addAttribute(KerberosCmdConfiguration.SCRIPT_USER_LOCKED_ATTRIBUTE_NAME, isUserLocked);
            }
        }

        bld.setObjectClass(oc);

        return bld.build();
    }

    private void readSearchOutput(final Process proc) throws ConnectorIOException {
        LOG.info("Processing script output ...");
        final BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        final StringBuilder buffer = new StringBuilder();
        final List<ConnectorObject> results = new ArrayList<>();
        String line;

        try {
            //TODO whitespace/string/newline formatting is built-in/assumed, if it differs code here
            while ((line = br.readLine()) != null) {
                LOG.ok("Handle search result item {0}", line);
                if (StringUtil.isNotBlank(kerberosCmdConfiguration.getScriptErrorResponse()) && line.contains(kerberosCmdConfiguration.getScriptErrorResponse())) {
                    throw new ConnectorIOException("Script failed with error response: " + line.toString());
                } else {
                    if (filter != null) {
                        buffer.append(line + " "); //this assumes script single result search has each flag on a newline
                    } else {
                        results.add(processSearchResult(line)); //this assumes script list all has each single result per line
                    }
                }
            }

            if (filter != null) {
                results.add(processSingleResult(buffer.toString().trim()));
            }
        } catch (IOException e) {
            LOG.error(e, "Error reading result items");
            throw new ConnectorIOException(e);
        }

        try {
            br.close();
        } catch (IOException e) {
            LOG.ok(e, "Error closing reader"); //swallow since process will be closed
        }

        LOG.ok("Found " + results.size() + " search results!");
        results.forEach(resultsHandler::handle);
    }
}

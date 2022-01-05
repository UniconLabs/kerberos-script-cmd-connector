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

import java.net.ConnectException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import edu.mines.kerberos.cmd.search.Operand;
import edu.mines.kerberos.cmd.methods.KerberosCmdCreate;
import edu.mines.kerberos.cmd.methods.KerberosCmdDelete;
import edu.mines.kerberos.cmd.methods.KerberosCmdExecuteQuery;
import edu.mines.kerberos.cmd.methods.KerberosCmdTest;
import edu.mines.kerberos.cmd.methods.KerberosCmdUpdate;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;


/**
 * KerberosCmdConnector
 *   Main connector class
 */
@ConnectorClass(configurationClass = KerberosCmdConfiguration.class, displayNameKey = "kerberosCmd.display")
public class KerberosCmdConnector implements Connector, SchemaOp, CreateOp, UpdateOp, DeleteOp, TestOp, SearchOp<Operand> {

    private static final Log LOG = Log.getLog(KerberosCmdConnector.class);

    private static KerberosCmdConfiguration kerberosCmdConfiguration;

    @Override
    public Configuration getConfiguration() {
        return kerberosCmdConfiguration;
    }

    @Override
    public void init(final Configuration configuration) {
        kerberosCmdConfiguration = (KerberosCmdConfiguration) configuration;
    }

    @Override
    public void dispose() {
        //NO
    }

    @Override
    public Uid create(final ObjectClass oc, final Set<Attribute> attributes, final OperationOptions oo) {
        if (LOG.isOk()) {
            LOG.ok("KerberosScript Create parameters:");
            LOG.ok("KerberosScript ObjectClass {0}", oc.getObjectClassValue());

            for (Attribute attr : attributes) {
                LOG.ok("KerberosScript Attribute {0}: {1}", attr.getName(), attr.getValue());
            }
            if (oo != null) {
                for (Map.Entry<String, Object> entrySet : oo.getOptions().entrySet()) {
                    final String key = entrySet.getKey();
                    final Object value = entrySet.getValue();
                    LOG.ok("OperationOptions {0}: {1}", key, value);
                }
            }
        }

        return new KerberosCmdCreate(oc, kerberosCmdConfiguration, attributes).execCreateCmd();
    }

    @Override
    public Uid update(final ObjectClass oc, final Uid uid, final Set<Attribute> attributes, final OperationOptions oo) {
        if (LOG.isOk()) {
            LOG.ok("KerberosScript Update parameters:");
            LOG.ok("KerberosScript ObjectClass {0}", oc.getObjectClassValue());
            LOG.ok("KerberosScript Uid: {0}", uid.getUidValue());
            for (Attribute attr : attributes) {
                LOG.ok("KerberosScript Attribute {0}: {1}", attr.getName(), attr.getValue());
            }
            if (oo != null) {
                for (Map.Entry<String, Object> entrySet : oo.getOptions().entrySet()) {
                    LOG.ok("   > OperationOptions {0}", entrySet.getKey() + ": " + entrySet.getValue());
                }
            }
        }

        return new KerberosCmdUpdate(oc, kerberosCmdConfiguration, uid, attributes).execUpdateCmd();
    }

    @Override
    public void delete(final ObjectClass oc, final Uid uid, final OperationOptions oo) {
        if (LOG.isOk()) {
            LOG.ok("KerberosScript Delete parameters:");
            LOG.ok("KerberosScript ObjectClass {0}", oc.getObjectClassValue());
            LOG.ok("KerberosScript Uid: {0}", uid.getUidValue());
            if (oo != null) {
                for (Map.Entry<String, Object> entrySet : oo.getOptions().entrySet()) {
                    LOG.ok("OperationOptions {0}: {1}", entrySet.getKey(), entrySet.getValue());
                }
            }
        }

        new KerberosCmdDelete(oc, kerberosCmdConfiguration, uid).execDeleteCmd();
    }

    @Override
    public void test() {
        LOG.ok("KerberosScript connection test");
        new KerberosCmdTest(kerberosCmdConfiguration).test();
    }

    @Override
    public void executeQuery(
            final ObjectClass oc,
            final Operand operand,
            final ResultsHandler rh,
            final OperationOptions oo) {

        if (LOG.isOk()) {
            LOG.ok("KerberosScript Search parameters:");
            LOG.ok("KerberosScript ObjectClass {0}", oc.getObjectClassValue());
            LOG.ok("KerberosScript Operand {0}", operand);
            if (oo != null) {
                for (Map.Entry<String, Object> entrySet : oo.getOptions().entrySet()) {
                    LOG.ok("OperationOptions {0}: {1}", entrySet.getKey(), entrySet.getValue());
                }
            }
        }

        try {
            new KerberosCmdExecuteQuery(oc, kerberosCmdConfiguration, operand, rh).execQuery();
        } catch (ConnectException ex) {
            LOG.error("KerberosScript Error in connection process", ex);
        }
    }

    @Override
    public Schema schema() {
        LOG.info(">>> schema started");

        final SchemaBuilder schemaBuilder = new SchemaBuilder(KerberosCmdConnector.class);
        try {
            final Set<AttributeInfo> attributes = new HashSet<>();

            attributes.add(OperationalAttributeInfos.PASSWORD);

            final AttributeInfoBuilder attrBuilder0 = new AttributeInfoBuilder();
            attrBuilder0.setName(KerberosCmdConfiguration.SCRIPT_USER_NAME_ATTRIBUTE_NAME);
            attrBuilder0.setRequired(true);
            attrBuilder0.setType(String.class);
            attrBuilder0.setMultiValued(false);
            attributes.add(attrBuilder0.build());

            final AttributeInfoBuilder attrBuilder1 = new AttributeInfoBuilder();
            attrBuilder1.setName(KerberosCmdConfiguration.SCRIPT_PASSWORD_ATTRIBUTE_NAME);
            attrBuilder1.setRequired(false);
            attrBuilder1.setType(GuardedString.class);
            attrBuilder1.setMultiValued(false);
            attributes.add(attrBuilder1.build());

            final AttributeInfoBuilder attrBuilder2 = new AttributeInfoBuilder();
            attrBuilder2.setName(KerberosCmdConfiguration.SCRIPT_USER_LOCKED_ATTRIBUTE_NAME);
            attrBuilder2.setRequired(false);
            attrBuilder2.setType(String.class);
            attrBuilder2.setMultiValued(false);
            attributes.add(attrBuilder2.build());

            final AttributeInfoBuilder attrBuilder3 = new AttributeInfoBuilder();
            attrBuilder3.setName(KerberosCmdConfiguration.SCRIPT_USER_FLAGS_ATTRIBUTE_NAME);
            attrBuilder3.setRequired(false);
            attrBuilder3.setType(String.class);
            attrBuilder3.setMultiValued(true);
            attrBuilder3.setCreateable(false);
            attrBuilder3.setUpdateable(false);
            attributes.add(attrBuilder3.build());

            final ObjectClassInfo ociInfoAccount =
                    new ObjectClassInfoBuilder()
                            .setType(kerberosCmdConfiguration.getObjectClass().getObjectClassValue())
                            .addAllAttributeInfo(attributes).build();
            schemaBuilder.defineObjectClass(ociInfoAccount);

        } catch (Exception ex) {
            LOG.error(ex, "Couldn't create schema for Kerberos CMD connector");
        }

        final Schema schema = schemaBuilder.build();
        LOG.info(">>> schema finished");

        return schema;
    }

    @Override
    public FilterTranslator<Operand> createFilterTranslator(final ObjectClass oc, final OperationOptions oo) {
        if (oc == null || (!oc.equals(ObjectClass.ACCOUNT))) {
            throw new IllegalArgumentException("KerberosScript Invalid objectclass not an ACCOUNT!");
        }
        return new KerberosCmdFilterTranslator();
    }

    public static void logScriptStatus(int statusCode) {
        LOG.ok("Process ended with status [" +
                KerberosCmdConfiguration.SCRIPT_EXIT_ERROR_CODES.get(statusCode) + "] and code " + statusCode + ".");

        if (statusCode != 0) {
            LOG.error("Kerberos Script ended with a non successful status of [" +
                KerberosCmdConfiguration.SCRIPT_EXIT_ERROR_CODES.get(statusCode) + "] and code " + statusCode + "!");
        }
    }
}

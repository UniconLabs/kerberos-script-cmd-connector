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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;


/**
 * CmdConfigurationTest
 */
public class KerberosCmdConfigurationTest extends KerberosCmdAbstractTest {

    /**
     * Tests setting and validating the parameters provided.
     */
    @Test
    public final void testValidate() {
        final KerberosCmdConfiguration config = new KerberosCmdConfiguration();
        try {
            config.validate();
            fail();
        } catch (RuntimeException e) {
            // expected because configuration is incomplete
            assertNotNull(e);
        }
    }
}

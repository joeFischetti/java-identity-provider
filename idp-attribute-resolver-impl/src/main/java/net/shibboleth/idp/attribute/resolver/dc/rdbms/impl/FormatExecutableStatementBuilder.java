/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.attribute.resolver.dc.rdbms.impl;

import net.shibboleth.utilities.java.support.primitive.DeprecationSupport;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport.ObjectType;

/**
 * Classpath placeholder for legacy configurations.
 * @deprecated
 */
@Deprecated public class FormatExecutableStatementBuilder
        extends net.shibboleth.idp.attribute.resolver.dc.rdbms.FormatExecutableStatementBuilder {

    /** Constructor. */
    public FormatExecutableStatementBuilder() {
        super();
        // V4 deprecation
        DeprecationSupport.warnOnce(ObjectType.CLASS,
                "net.shibboleth.idp.attribute.resolver.dc.rdbms.impl.FormatExecutableStatementBuilder", 
                null, 
                "net.shibboleth.idp.attribute.resolver.dc.rdbms.FormatExecutableStatementBuilder");
    }
}

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

package net.shibboleth.idp.profile.context.navigate;

import java.lang.reflect.InvocationTargetException;

import javax.script.ScriptException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.utilities.java.support.testing.TestSupport;

/**
 *
 */
public class ScriptedFunctionTest {
    
    static final String STRING_RETURN_7 = "new java.lang.String(\"String\");";
    static final String STRING_RETURN_8 = "JavaString=Java.type(\"java.lang.String\"); new JavaString(\"String\");";
    static final String INTEGER_RETURN_7 = "new java.lang.Integer(37);";
    static final String INTEGER_RETURN_8 = "JavaInteger=Java.type(\"java.lang.Integer\"); new JavaInteger(37);";
    
    private String stringReturn() {
        if (TestSupport.isJavaV8OrLater()) {
            return STRING_RETURN_8;
        }
        return STRING_RETURN_7;
    }
    
    private String integerReturn() {
        if (TestSupport.isJavaV8OrLater()) {
            return INTEGER_RETURN_8;
        }
        return INTEGER_RETURN_7;
    }

    
    @Test public void simpleScript() throws ScriptException {
        final ProfileRequestContext prc = new ProfileRequestContext();
        
        final Object string = ScriptedContextLookupFunction.inlineScript(stringReturn()).apply(prc);

        String s = (String) string;
        Assert.assertEquals(s, "String");
        
        final Integer integer = (Integer) ScriptedContextLookupFunction.inlineScript(integerReturn()).apply(prc);
        Assert.assertEquals(integer.intValue(), 37);
    }
    
    @Test public void custom() throws ScriptException {
        final ProfileRequestContext prc = new ProfileRequestContext();
        
        final ScriptedContextLookupFunction<ProfileRequestContext> script = ScriptedContextLookupFunction.inlineScript("custom;");
        script.setCustomObject("String");
        Assert.assertEquals(script.apply(prc), "String");
 
        script.setCustomObject(Integer.valueOf(37));
        Assert.assertEquals(script.apply(prc), Integer.valueOf(37));
    }    
    
    
    @Test public void withType() throws ScriptException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        final ProfileRequestContext prc = new ProfileRequestContext();

        final ScriptedContextLookupFunction<ProfileRequestContext> script1 = ScriptedContextLookupFunction.inlineScript(stringReturn(), Object.class);
        
        final String string = (String) script1.apply(prc);
        Assert.assertEquals(string, "String");
        
        Assert.assertEquals(ScriptedContextLookupFunction.inlineScript(stringReturn(), String.class).apply(prc), "String");
        
        Assert.assertNull(ScriptedContextLookupFunction.inlineScript(stringReturn(), Integer.class).apply(prc));
        
        final Integer integer = (Integer) ScriptedContextLookupFunction.inlineScript(integerReturn()).apply(prc);
        Assert.assertEquals(integer.intValue(), 37);
        
    }

    @Test public void messageContext() throws ScriptException {
        final ScriptedContextLookupFunction<MessageContext> script1 = ScriptedContextLookupFunction.inlineMessageContextScript(stringReturn(), Object.class);
        
        Assert.assertEquals(script1.apply(new MessageContext()), "String");
        Assert.assertEquals(script1.apply(null), "String");
    }
}

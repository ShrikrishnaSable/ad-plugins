/*
 * Copyright 1998-2009 by SLIB,
 * 70 rue Villette, 69003 Lyon, France
 * All rights reserved.
 *
 * This software is the confidential and proprietary information
 * of SLIB. (&quot;Confidential Information&quot;).  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with SLIB.
 */

package org.sonar.plugins.ad;

import java.util.ArrayList;
import java.util.List;

import org.sonar.api.Extension;
import org.sonar.api.Plugin;
import org.sonar.api.Properties;
import org.sonar.api.Property;

@Properties({

    @Property(key="dnsDomain", name="dnsDomain", description = "DNS Domain name"),
    @Property(key="dnsDomainDn", name="dnsDomainDn", description = "DNS Domain name DN"),
    @Property(key="adServer", name="adServer", description = "Active Directory server name")

})

/**
 * <code>AuthenticatorPlugin</code>
 *
 * @version	$Id: AuthenticatorPlugin.java 11246 2009-12-17 17:23:03Z gomezhe $
 * @author	$Author: gomezhe $
 */
public class AuthenticatorPlugin implements Plugin {

    public String getKey()
    {
        return "adauth";
    }

    public String getName()
    {
        return "AD Authenticator";
    }

    public String getDescription()
    {
        return "Plugs authentication mechanism to an ActiveDirectory server to delegate passwords management.";
    }

    public List<Class<? extends Extension>> getExtensions() {

        List<Class<? extends Extension>> list = new ArrayList<Class<? extends Extension>>();
        list.add(Authenticator.class);
        return list;
    }
}

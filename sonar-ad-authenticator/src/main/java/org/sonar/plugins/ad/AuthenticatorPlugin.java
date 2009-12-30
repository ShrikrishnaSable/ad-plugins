/*
 * Sonar, open source software quality management tool.
 * Copyright (C) 2009 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * Sonar is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * Sonar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Sonar; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
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

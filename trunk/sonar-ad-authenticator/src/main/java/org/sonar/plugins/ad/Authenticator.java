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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.apache.commons.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.ServerExtension;
import org.sonar.api.security.LoginPasswordAuthenticator;


/**
 * <code>Authenticator</code>
 *
 * @version	$Id: Authenticator.java 11248 2009-12-17 17:26:00Z gomezhe $
 * @author  $Author: gomezhe $
 */
public class Authenticator implements LoginPasswordAuthenticator, ServerExtension {

    private String           ldapServer;

    private String           dnsDomain;

    private String           dnsDomainDn;

    private Attribute        serversAttribute;

    private Configuration    configuration;


    public Authenticator(Configuration configuration)
    {
        this.configuration = configuration;
    }

    /***
     * Get the DNS domain (ie: mycorp.org)
     *
     * @return
     * @throws UnknownHostException
     */
    private String getDnsDomain() throws UnknownHostException
    {
        // get dns domain
        String lDnsDomain = null;

        if ( lDnsDomain == null ) {
            String lLocalhost = InetAddress.getLocalHost().getCanonicalHostName();
            String[] lParts = lLocalhost.split( "[.]" );
            if ( lParts.length > 1 )
                lDnsDomain = lParts[ lParts.length - 2 ] + "." + lParts[ lParts.length - 1 ];
        }

        return (lDnsDomain);
    }

    /***
     * Get the DNS DN domain (ie: mycorp.org)
     *
     * @return
     * @throws UnknownHostException
     */
    private String getDnsDomainDn(String lDnsDomain)
    {
        // get dns domain DN
        StringBuilder lDnsDomainDnBuilder = new StringBuilder();
        boolean lFirst = true;
        for ( String lName : lDnsDomain.split( "[.]" ) ) {
            if ( lFirst )
                lFirst = false;
            else
                lDnsDomainDnBuilder.append( "," );
            lDnsDomainDnBuilder.append( "DC=" );
            lDnsDomainDnBuilder.append( lName );
        }
        String lDnsDomainDn = lDnsDomainDnBuilder.toString();

        return (lDnsDomainDn);
    }

    private boolean authenticate( String pUser, String pPassword, String pServer, String pDomain, String pDnsDomainDn ) throws AuthenticationException
    {
        boolean lAuthenticated = false;
        Logger lLogger = LoggerFactory.getLogger(Authenticator.class);

        try {
            // compute user principal
        String lFuncDomain = pDomain; //"mycorp.com";
        String lPrincipal = pUser + "@" + lFuncDomain;

        // bind principal to current Active Directory server
        Properties lLdapEnv = new Properties();
        lLdapEnv.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
        lLdapEnv.put( Context.SECURITY_AUTHENTICATION, "simple" );
        lLdapEnv.put( Context.SECURITY_PRINCIPAL, lPrincipal );
        lLdapEnv.put( Context.SECURITY_CREDENTIALS, pPassword );
        lLdapEnv.put( Context.PROVIDER_URL, "ldap://" + pServer );
        lLdapEnv.put( Context.REFERRAL, "follow" );

        DirContext lLdapCtx = new InitialLdapContext( lLdapEnv, null );

        SearchControls lSearchControls = new SearchControls();
        lSearchControls.setSearchScope( SearchControls.SUBTREE_SCOPE );
        NamingEnumeration<SearchResult> lEnum2 = lLdapCtx.search( pDnsDomainDn, "(& (userPrincipalName="
        + lPrincipal + ")(objectClass=user))", lSearchControls );

        if ( !lEnum2.hasMore() )
            lLogger.info( "authentication was successful but cannot locate the user information for " + pUser );

        // user is authenticated
        lAuthenticated = true;

        // close connection to Active Directory server
            lLdapCtx.close();
        }
        catch ( Exception e ) {
            lLogger.error("Error while joining AD Server " + pServer + " :", e );
            throw new AuthenticationException("Error while joining AD Server " + pServer);
        }

        if (lLogger.isDebugEnabled())
            if (lAuthenticated)
                lLogger.debug("user " + pUser + " has been authenticated on server " + pServer);
            else
                lLogger.debug("user " + pUser + " cannot be authenticated on server " + pServer);

        return (lAuthenticated);
    }


    public boolean authenticate( String user, String password ) {

        try
        {
            // LDAP server set, try with it
            if (ldapServer != null)
                return (authenticate(user, password, ldapServer, dnsDomain, dnsDomainDn));

            NamingEnumeration<String> lEnum = (NamingEnumeration<String>) serversAttribute.getAll();

            while (lEnum.hasMore()) {
                String lSrvRecord = lEnum.next();
                String[] lSrvData = lSrvRecord.split( " " );
                String lAdServer = ( lSrvData[ 3 ].endsWith( "." ) ? lSrvData[ 3 ].substring( 0, lSrvData[ 3 ].length() - 1 ) : lSrvData[ 3 ] ) + ":" + lSrvData[ 2 ];

                if (authenticate(user, password, lAdServer, dnsDomain, dnsDomainDn))
                    return (true);
            }
        }
        catch (NamingException ne)
        {
            LoggerFactory.getLogger(Authenticator.class).error("error while getting server attributes", ne );
        }

        return (false);
    }

    public void init() {

        LoggerFactory.getLogger(Authenticator.class).info("Initializing");

        try {
            dnsDomain = configuration.getString("ad.dnsdomain", null);

            if (dnsDomain == null)
                dnsDomain = getDnsDomain();

            dnsDomainDn = configuration.getString("ad.dnsdomaindn", null);

            if (dnsDomainDn == null)
                dnsDomainDn = getDnsDomainDn(dnsDomain);

            ldapServer = configuration.getString("ad.ldapserver", null);

            if (ldapServer == null) {
                // get Active Directory servers
                DirContext lDnsCtx = new InitialDirContext();
                Attributes lSrvAttrs = lDnsCtx.getAttributes("dns:/_ldap._tcp."
                        + dnsDomain, new String[] { "srv" });
                serversAttribute = lSrvAttrs.get("srv");
            }

            LoggerFactory.getLogger(Authenticator.class).info("Will use dnsDomain=" + dnsDomain + " dnsDomainDn=" + dnsDomainDn +
                " ldapServer=" + ldapServer);

        } catch (Exception e) {

            LoggerFactory.getLogger(Authenticator.class).error( "exception while initializing:" + e );
        }
    }


}

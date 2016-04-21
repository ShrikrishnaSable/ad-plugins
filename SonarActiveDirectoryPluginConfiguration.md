# Introduction #

sonar-ad-authenticator is a Sonar Authenticator Plugin to be used when you want your Sonar users to check their login/password against ActiveDirectory.

This plugin require just zero configuration, and avoid the pain of LDAP settings.

# Preparation #

sonar authenticator plugins only check if a login/password combination works against LDAP or in our case, ActiveDirectory.

You should have created previously users accounts in sonar with its admin interface.

# Configuration #

  * Copy the **sonar-ad-authenticator** jar to your sonar extensions/plugins directory
  * Add the following 2 lines to your sonar.properties file

```
sonar.authenticator.class: org.sonar.plugins.ad.Authenticator
sonar.authenticator.ignoreStartupFailure: false
```


Restart Sonar and try to log to Sonar. Enter the login / password, the combination will be checked against your AD server.
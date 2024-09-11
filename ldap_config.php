<?php
/*
*Developer by HANSMILLER ALVES
*Mail : miller_programador@outlook.com
*/
$AUTHCFG['authType'] = 'LDAP';
$AUTHCFG['ldap'] = array(
    'server' => 'YOUR_SRV',
    'port' => 389,
    'basedn' => 'DC=in,DC=YOUR_DOMAIN,DC=COUNTRY',
    'username' => 'YOUR_USERNAME',
    'password' => 'YOUR_PASSWORD',
    'userdn' => 'DC=in,DC=USER_DN,DC=pt',
    'userfilter' => '(&(objectClass=user)(sAMAccountName=%s))',
    'binddn' => 'in\%s',
    'bindattr' => 'sAMAccountName',
    'attributes' => array(
        'dn' => 'distinguishedName',
        'firstname' => 'givenName',
        'lastname' => 'sn',
        'email' => 'mail'
    ),
    'bindRequiresDn' => false,
    'accountDomainName' => 'YOUR_ACCOUNT_DOMAIN_NAME',
    'accountDomainNameShort' => 'IN'
);
putenv('LDAPTLS_REQCERT=never');
/*** add this code block at the end of the config.inc.php file ***/ 

//LDAP outsource file
if (file_exists('modules/LDAPSync/ldap_config.php')) {
    // LDAP Sync Configuration
	require_once 'modules/LDAPSync/ldap_config.php';

}

<?php
/*
*Developer by HANSMILLER ALVES
*Mail : miller_programador@outlook.com
*/
function ldapUserSync($username, $password, $userdata) {
    global $adb;
    ldap_debug_log("ldapUserSync called for user: $username");
    ldap_debug_log("User data: " . print_r($userdata, true));
    
    // Garantir que temos valores padrão para lastname e email
    $userdata['lastname'] = !empty($userdata['lastname']) ? $userdata['lastname'] : '';
    $userdata['email'] = !empty($userdata['email']) ? $userdata['email'] : $username . '@default.com';
    
    // Verificar se o usuário já existe no vtigerCRM
    $query = "SELECT id, accesskey FROM vtiger_users WHERE user_name = ?";
    $result = $adb->pquery($query, array($username));
    
    if ($adb->num_rows($result) == 0) {
        ldap_debug_log("User $username does not exist in vtigerCRM. Creating new user.");
        // O usuário não existe, vamos criá-lo
        $userdata['password'] = $password; // Adicionar a senha LDAP aos dados do usuário
        $userId = createVtigerUser($username, $userdata);
        if ($userId) {
            ldap_debug_log("User $username created with ID: $userId");
            finalizeUserSetup($userId, $userdata);
            clearUserCache($userId);
            checkUserConsistency($userId);
            
            // Adicionar a chamada para finalizeLDAPUser
            require_once('modules/LDAPSync/LDAPUserFinalizer.php');
            if (finalizeLDAPUser($userId, $password)) {
                ldap_debug_log("LDAP user finalization completed for user ID: $userId");
            } else {
                ldap_debug_log("Failed to finalize LDAP user for user ID: $userId");
            }
        } else {
            ldap_debug_log("Failed to create user $username");
            return false;
        }
    } else {
        // O usuário já existe, vamos atualizar as informações
        $userId = $adb->query_result($result, 0, 'id');
        $accesskey = $adb->query_result($result, 0, 'accesskey');
        ldap_debug_log("User $username already exists with ID: $userId");
        
        // Atualizar as informações do usuário, incluindo a senha
        updateUserInfo($userId, $accesskey, $userdata, $password);
        finalizeUserSetup($userId, $userdata);
        clearUserCache($userId);
        checkUserConsistency($userId);
        
        // Adicionar a chamada para finalizeLDAPUser também para usuários existentes
        require_once('modules/LDAPSync/LDAPUserFinalizer.php');
        if (finalizeLDAPUser($userId, $password)) {
            ldap_debug_log("LDAP user finalization completed for existing user ID: $userId");
        } else {
            ldap_debug_log("Failed to finalize LDAP user for existing user ID: $userId");
        }
    }
    
    return $userId;
}

function updateUserInfo($userId, $accesskey, $userdata, $password) {
    global $adb;
    
    // Primeiro, vamos buscar os dados existentes do usuário
    $query = "SELECT first_name, last_name, email1 FROM vtiger_users WHERE id = ?";
    $result = $adb->pquery($query, array($userId));
    $existingData = $adb->fetch_array($result);

    // Agora, vamos usar os dados do LDAP apenas se estiverem disponíveis, caso contrário, manteremos os dados existentes
    $firstName = !empty($userdata['firstname']) ? $userdata['firstname'] : $existingData['first_name'];
    $lastName = !empty($userdata['lastname']) ? $userdata['lastname'] : $existingData['last_name'];
    $email = !empty($userdata['email']) ? $userdata['email'] : $existingData['email1'];

    // Se ainda não houver dados, usamos valores padrão
    $firstName = !empty($firstName) ? $firstName : $userdata['user_name'];
    $lastName = !empty($lastName) ? $lastName : 'Atualize esse Campo';
    $email = !empty($email) ? $email : $userdata['user_name'] . '@default.com';

    if (empty($accesskey)) {
        $accesskey = generateAccessKey();
    }
    
    $hashedPassword = generatePasswordHash($password);
    
    $query = "UPDATE vtiger_users SET 
              accesskey = ?, 
              first_name = ?, 
              last_name = ?, 
              email1 = ?, 
              user_password = ?, 
              confirm_password = ?,
              crypt_type = ?
              WHERE id = ?";
    
    $params = array(
        $accesskey,
        $firstName,
        $lastName,
        $email,
        $hashedPassword,
        $hashedPassword,
        'PHASH',
        $userId
    );
    
    $result = $adb->pquery($query, $params);
    
    if ($result) {
        ldap_debug_log("Updated user info for user ID $userId. AccessKey: $accesskey, First Name: $firstName, Last Name: $lastName, Email: $email");
    } else {
        ldap_debug_log("Failed to update user info for user ID $userId");
    }
}

function createVtigerUser($username, $userdata) {
    global $adb;
    
    // Usar a senha do LDAP
    $password = $userdata['password'] ?? '';
    if (empty($password)) {
        ldap_debug_log("Error: No password provided for user $username");
        return false;
    }
    $hashedPassword = generatePasswordHash($password);
    
    // Gerar uma nova chave de acesso
    $accesskey = generateAccessKey();
    
    // Preparar os dados do usuário
    $firstName = !empty($userdata['firstname']) ? $userdata['firstname'] : $username;
    $lastName = !empty($userdata['lastname']) ? $userdata['lastname'] : 'Atualize esse Campo';
    $userLabel = $username;
    $email = !empty($userdata['email']) ? $userdata['email'] : $username . '@default.com';
    
    // Inserir o novo usuário
    $query = "INSERT INTO vtiger_users 
              (user_name, user_password, confirm_password, first_name, last_name, 
               status, is_admin, date_format, hour_format, time_zone, currency_id, theme, 
               language, crypt_type, userlabel, accesskey, email1) 
              VALUES 
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    $params = array(
        $username, 
        $hashedPassword, 
        $hashedPassword,
        $firstName, 
        $lastName, 
        'Active', 
        'off', 
        'dd-mm-yyyy', 
        '12', 
        'UTC', 
        '1', 
        'softed', 
        'en_us',
        'PHASH',
        $userLabel,
        $accesskey,
        $email
    );
    
    $result = $adb->pquery($query, $params);
    
    if ($result) {
        $userId = $adb->getLastInsertID();
        ldap_debug_log("New user created with ID: $userId, AccessKey: $accesskey, First Name: $firstName, Last Name: $lastName, Email: $email");
        
        // Verificar se o accesskey foi realmente inserido
        $checkQuery = "SELECT accesskey FROM vtiger_users WHERE id = ?";
        $checkResult = $adb->pquery($checkQuery, array($userId));
        $storedAccessKey = $adb->query_result($checkResult, 0, 'accesskey');
        
        if (empty($storedAccessKey)) {
            ldap_debug_log("AccessKey not stored properly. Updating...");
            $updateQuery = "UPDATE vtiger_users SET accesskey = ? WHERE id = ?";
            $adb->pquery($updateQuery, array($accesskey, $userId));
        }
        
        // Adicionar entrada na tabela vtiger_user2role
        assignPublicRole($userId);
        
        // Criar arquivo de privilégios do usuário
        require_once('modules/Users/CreateUserPrivilegeFile.php');
        createUserPrivilegesfile($userId);
        
        return $userId;
    }
    
    ldap_debug_log("Failed to create new user in database");
    return false;
}

function finalizeUserSetup($userId, $userdata) {
    global $adb;
    
    // Atualizar campos adicionais que podem ser necessários
    $query = "UPDATE vtiger_users SET 
              status = 'Active',
              is_admin = 'off',
              end_hour = '23:00',
              start_hour = '00:00',
              isduplicateallowed = '1',
              is_owner = '0',
              internal_mailer = '1',
              reminder_interval = '1 Minute',
              calendarsharedtype = 'public',
              default_record_view = 'Summary',
              leftpanelhide = '0',
              rowheight = 'medium',
              defaulteventstatus = 'Planned',
              defaultactivitytype = 'Call',
              hidecompletedevents = '0',
              phone_crm_extension = '',
              imagename = '',
              currency_grouping_pattern = '123,456,789',
              currency_decimal_separator = '.',
              currency_grouping_separator = ',',
              currency_symbol_placement = '$1.0'
              WHERE id = ?";
    
    $adb->pquery($query, array($userId));
    
    // Criar ou atualizar entradas em tabelas relacionadas
    $tables = array(
        'vtiger_user2role',
        'vtiger_users2group',
        'vtiger_user_module_preferences',
        'vtiger_homestuff',
        'vtiger_user_module_preferences'
    );
    
    foreach ($tables as $table) {
        $checkQuery = "SELECT 1 FROM $table WHERE userid = ?";
        $result = $adb->pquery($checkQuery, array($userId));
        if ($adb->num_rows($result) == 0) {
            $insertQuery = "INSERT INTO $table (userid) VALUES (?)";
            $adb->pquery($insertQuery, array($userId));
        }
    }
    
    // Recriar o arquivo de privilégios do usuário
    require_once('modules/Users/CreateUserPrivilegeFile.php');
    createUserPrivilegesfile($userId);
    
    ldap_debug_log("Finalized setup for user ID: $userId");
}

// Função para gerar uma chave de acesso aleatória
function generateAccessKey() {
    return substr(md5(time() . rand(100000, 999999)), 0, 32);
}

function assignPublicRole($userId) {
    global $adb;

    // Obter o ID da função
    $query = "SELECT roleid FROM vtiger_role WHERE rolename = 'Franchisados'";
    $result = $adb->pquery($query, array());
    
    if ($adb->num_rows($result) > 0) {
        $roleId = $adb->query_result($result, 0, 'roleid');

        // Atribuir a função "Franch" ao usuário
        $query = "INSERT INTO vtiger_user2role (userid, roleid) VALUES (?, ?)";
        $adb->pquery($query, array($userId, $roleId));
        ldap_debug_log("Assigned Franchisados role to user ID: $userId");
    } else {
        ldap_debug_log("Franchisados role not found");
    }
}

function generateRandomPassword($length = 12) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $password;
}

function generatePasswordHash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

function ldap_debug_log($message) {
    error_log(date('Y-m-d H:i:s') . ': ' . $message . "\n", 3, '/tmp/php_log/vtiger_ldap_debug.log');
}

function clearUserCache($userId) {
    require_once('includes/runtime/Cache.php');
    VTCacheUtils::clearUserCache($userId);
    ldap_debug_log("Cleared cache for user ID: $userId");
}

function checkUserConsistency($userId) {
    global $adb;
    
    $query = "SELECT * FROM vtiger_users WHERE id = ?";
    $result = $adb->pquery($query, array($userId));
    
    if ($adb->num_rows($result) == 0) {
        ldap_debug_log("User consistency check failed: User ID $userId not found");
        return false;
    }
    
    $userData = $adb->fetch_array($result);
    
    // Verificar campos essenciais
    $essentialFields = ['user_name', 'user_password', 'first_name', 'last_name', 'email1', 'status', 'crypt_type'];
    foreach ($essentialFields as $field) {
        if (empty($userData[$field])) {
            ldap_debug_log("User consistency check failed: Field '$field' is empty for User ID $userId");
            return false;
        }
    }
    
    // Verificar se o usuário tem uma função atribuída
    $roleQuery = "SELECT roleid FROM vtiger_user2role WHERE userid = ?";
    $roleResult = $adb->pquery($roleQuery, array($userId));
    if ($adb->num_rows($roleResult) == 0) {
        ldap_debug_log("User consistency check failed: No role assigned for User ID $userId");
        return false;
    }
    
    ldap_debug_log("User consistency check passed for User ID $userId");
    return true;

}

?>
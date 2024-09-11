<?php
/*
*Developer by HANSMILLER ALVES
*Mail : miller_programador@outlook.com
*/
require_once('include/database/PearDatabase.php');
require_once('include/utils/UserInfoUtil.php');
require_once('modules/Users/CreateUserPrivilegeFile.php');

function finalizeLDAPUser($userId, $password) {
    global $adb, $current_user;

    // Salvar o usuário atual
    $originalCurrentUser = $current_user;

    // Simular que o usuário atual é o administrador
    $adminUser = CRMEntity::getInstance('Users');
    $adminUser->retrieveCurrentUserInfoFromFile(1); // 1 é geralmente o ID do admin
    $current_user = $adminUser;

    // Buscar informações do usuário LDAP
    $query = "SELECT * FROM vtiger_users WHERE id = ?";
    $result = $adb->pquery($query, array($userId));
    
    if ($adb->num_rows($result) == 0) {
        ldap_debug_log("User not found for ID: $userId");
        return false;
    }
    
    $userData = $adb->fetch_array($result);

    // Criar um objeto de usuário para o usuário LDAP
    $userInstance = CRMEntity::getInstance('Users');
    $userInstance->retrieve_entity_info($userId, 'Users');

    // Simular a edição e salvamento do usuário
    $userInstance->mode = 'edit';
    $userInstance->id = $userId;
    foreach ($userData as $key => $value) {
        $userInstance->column_fields[$key] = $value;
    }

    // Adicionar um pequeno ajuste ao last_name para forçar uma "mudança"
    $userInstance->column_fields['last_name'] .= ' ';

    // Salvar o usuário
    $userInstance->save('Users');

    // Remover o espaço extra do last_name e atualizar a senha
    $hashedPassword = generatePasswordHash($password);
    $adb->pquery("UPDATE vtiger_users SET last_name = TRIM(last_name), user_password = ?, confirm_password = ?, crypt_type = 'PHASHE' WHERE id = ?", array($hashedPassword, $hashedPassword, $userId));

    // Forçar a atualização de alguns campos importantes
    $adb->pquery("UPDATE vtiger_users SET status = 'Active', is_owner = '1' WHERE id = ?", array($userId));

    // Recriar o arquivo de privilégios do usuário
    createUserPrivilegesfile($userId);
    
    // Limpar o cache do usuário
    require_once('includes/runtime/Cache.php');
    VTCacheUtils::clearUserCache($userId);
    
    // Restaurar o usuário original
    $current_user = $originalCurrentUser;

    ldap_debug_log("Finalized LDAP user setup for ID: $userId. Updated password and simulated last_name edit.");
    return true;
}

function generatePasswordHash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

function ldap_debug_log($message) {
    error_log(date('Y-m-d H:i:s') . ': ' . $message . "\n", 2, STDERR);
}

?>
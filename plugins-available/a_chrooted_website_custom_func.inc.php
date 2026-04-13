<?php

/*
Plugin Name: a_chrooted_website_custom_func
Description: Pre-cleanup plugin to UNLOCK immutable files before ISPConfig attempts to modify/delete them.
*/

class a_chrooted_website_custom_func {

    var $plugin_name = 'a_chrooted_website_custom_func';
    var $class_name = 'a_chrooted_website_custom_func';

    function onLoad() {
        global $app;
        // Ensure the system class is loaded for exec_safe
        $app->uses('system');

        // Hook into Shell User events (Update/Delete)
        $app->plugins->registerEvent('shell_user_insert', $this->plugin_name, 'oninsert_shell_user');
        $app->plugins->registerEvent('shell_user_update', $this->plugin_name, 'unlock_shell_user');
        $app->plugins->registerEvent('shell_user_delete', $this->plugin_name, 'unlock_shell_user');
        
        // Hook into Website events (for the 'web4' service user)
        $app->plugins->registerEvent('web_domain_update', $this->plugin_name, 'unlock_web_user');
        $app->plugins->registerEvent('web_domain_delete', $this->plugin_name, 'unlock_web_user');
    }
    
    function oninsert_shell_user($event_name, $data) {
        global $app;
        $app->log('A-PLUGIN: --------- "oninsert_shell_user" - STARTED >>>', LOGLEVEL_DEBUG);
        //$app->log("A-PLUGIN: (oninsert_shell_user)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);
        
        // Use 'new' data to ensure we catch the new directory structure
        $user_dir = $data['new']['dir']; 
        $username = $data['new']['username'];
        
        // Call with the 'web4' base-dir.
        // Example: "/var/www/clients/client3/web4"
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the "document_root" directly...
        // ... we need to potentionally unlock this file also, because it is getting potentionally locked in the Z-PLUGIN.
        $this->unlock_keys(null, $username, $user_dir);
        
        $app->log('A-PLUGIN: <<< "oninsert_shell_user" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    function unlock_shell_user($event_name, $data) {
        global $app;
        $app->log('A-PLUGIN: --------- "unlock_shell_user" - STARTED >>>', LOGLEVEL_DEBUG);
        //$app->log("A-PLUGIN: (unlock_shell_user)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);
        
        // Use 'old' data to ensure we catch the existing directory structure
        $user_dir = $data['old']['dir']; 
        $username = $data['old']['username'];
        $this->unlock_keys($user_dir, $username);
        
        // Call with the 'web4' base-dir.
        // Example: "/var/www/clients/client3/web4"
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the "document_root" directly...
        // ... we need to potentionally unlock this file also, because it is getting potentionally locked in the Z-PLUGIN.
        $this->unlock_keys(null, $username, $user_dir);
        
        $app->log('A-PLUGIN: <<< "unlock_shell_user" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    function unlock_web_user($event_name, $data) {
        global $app;
        $app->log('A-PLUGIN: --------- "unlock_web_user" - STARTED >>>', LOGLEVEL_DEBUG);
        $app->log("A-PLUGIN: (unlock_web_user)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);
        
        // Construct the 'web4' home path: [document_root]/home/[system_user]
        // Example: "/var/www/clients/client3/web4/home/web4"
        $web_user_home = $data['old']['document_root'] . '/home/' . $data['old']['system_user'];
        $username = $data['old']['system_user'];

        // For the web users we pass the explicit path because they don't follow the shell-users /home structure
        $this->unlock_keys(null, $username, $web_user_home);
        
        // Call with the 'web4' base-dir.
        // Example: "/var/www/clients/client3/web4"
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the "document_root" directly...
        // ... we need to potentionally unlock this file also, because it is getting potentionally locked in the Z-PLUGIN.
        $this->unlock_keys(null, $username, $data['old']['document_root']);
        
        // EXTRA CLEANUP for Delete Event: Force Unmount
        // This ensures standard ISPConfig plugins don't fail when trying to rm -rf the docroot
        if ($event_name == 'web_domain_delete') {
            $jail_root = $data['old']['document_root'];
            $this->remove_mounts($jail_root);
        }
        
        $app->log('A-PLUGIN: <<< "unlock_web_user" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    private function unlock_keys($jail_root, $username, $explicit_home = null) {
        global $app;
        
        // Determine path
        if ($explicit_home) {
            $ssh_dir = $explicit_home . '/.ssh';
        } else {
            // Standard Jailkit path: /var/www/.../home/shu_user/.ssh
            $ssh_dir = rtrim($jail_root, '/') . '/home/' . $username . '/.ssh';
        }

        $key_file = $ssh_dir . '/authorized_keys';

        if (file_exists($key_file)) {
            // REMOVE Immutable Bit so ISPConfig can do its work
            $app->system->exec_safe("chattr -i ?", $key_file);
            $app->log("A-PLUGIN: Unlocked immutable file: $key_file", LOGLEVEL_DEBUG);
        }
        else {
        	$app->log("A-PLUGIN: \"$key_file\" attempted to be unlocked, but does not exist!", LOGLEVEL_DEBUG);
        }
    }

    // Ported from Z-Plugin to allow early cleanup
    private function remove_mounts($jail_root) {
        global $app;
        $mounts = array($jail_root . '/proc', $jail_root . '/dev/pts');
        $lines = file('/etc/fstab', FILE_IGNORE_NEW_LINES);
        $new_fstab = [];
        $changed = false;

        foreach ($lines as $line) {
            if (trim($line) == '') continue;
            $keep = true;
            foreach ($mounts as $m) {
                if (strpos($line, $m) !== false) {
                    $app->system->exec_safe("umount ? 2>/dev/null", $m);
                    $keep = false;
                    $changed = true;
                }
            }
            if ($keep) $new_fstab[] = $line;
        }

        if ($changed) {
            file_put_contents('/etc/fstab', implode("\n", $new_fstab) . "\n");
            $app->system->exec_safe("systemctl daemon-reload");
            $app->log("A-PLUGIN: Forced unmount for delete event: $jail_root", LOGLEVEL_DEBUG);
        }
    }
}
?>
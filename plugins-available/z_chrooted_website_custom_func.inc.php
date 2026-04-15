<?php /*
MIT License

Copyright (c) 2026 Talutah W Elan <talutahelan@gmail.com>

Git repo: https://github.com/talutahelan-star/ispconfig-advanced-jailkit-tools
Discussion board: asd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
Plugin Name: z_chrooted_website_custom_func
Description: 
    Master Security & Hygiene Plugin for Jailkit Environments.
    1. IMMUTABILITY: Enforces strict immutability (chattr +i) on SSH keys and directories to prevent unauthorized modification.
    2. HYGIENE: Manages system mounts (/proc, /dev/pts) dynamically based on active users and PHP-FPM chroot settings, preventing "Zombie Directories."
    3. ENVIRONMENT: Injects critical environment variables (env[HOME]) into PHP-FPM pools for chrooted setups.
    4. PROVISIONING: Executes custom provisioning script (padm_shelluser_provision.sh) for new/updated shell users.
    5. CLEANUP: Performs forceful cleanup (unmounting and deletion) when websites or shell users are deleted.
    Runs LAST (Post-Action) to ensure all standard ISPConfig operations are secured.
*/

class z_chrooted_website_custom_func {

    var $plugin_name = 'z_chrooted_website_custom_func';
    var $class_name = 'z_chrooted_website_custom_func';

    function onLoad() {
        global $app;
        $app->uses('system,getconf'); // Added getconf to load server configurations

        // Shell User Events
        $app->plugins->registerEvent('shell_user_insert', $this->plugin_name, 'update_shell');
        $app->plugins->registerEvent('shell_user_update', $this->plugin_name, 'update_shell');
        $app->plugins->registerEvent('shell_user_delete', $this->plugin_name, 'delete_shell');

        // Website Events (To secure the 'web4' user)
        $app->plugins->registerEvent('web_domain_insert', $this->plugin_name, 'update_web');
        $app->plugins->registerEvent('web_domain_update', $this->plugin_name, 'update_web');
        
        // Added delete event to handle cleanup of mounts when site is removed (v20)
        $app->plugins->registerEvent('web_domain_delete', $this->plugin_name, 'delete_web');
    }

    // --- SHELL USER LOGIC ---

    function update_shell($event_name, $data) {
        global $app;
        $app->log('Z-PLUGIN: --------- "update_shell" - STARTED >>>', LOGLEVEL_DEBUG);
        $app->log("Z-PLUGIN: Shell Update Event: " . $event_name, LOGLEVEL_DEBUG);
        $app->log("Z-PLUGIN: (update_shell)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);

        $new_user = $data['new'];
        $jail_root = rtrim($new_user['dir'], '/');
        $domain_id = $new_user['parent_domain_id'];

        // 1. JAILKIT LOGIC (Mounts)
        // Refactored to use conditional logic (v19)
        // This handles both adding (if conditions met) and removing (if conditions lost)
        $this->manage_proc_and_devpts($jail_root, $domain_id);

        // 2. PROVISIONING LOGIC (New v22)
        // Execute custom bash provisioning script
        $this->execute_padm_provisioning($new_user);

        // 3. SECURITY LOGIC (Lock Keys)
        // Path: [jail_root]/home/[username]
        $ssh_home = $jail_root . '/home/' . $new_user['username'];
        $this->secure_ssh_directory($ssh_home);
        
        // Target: /var/www/clients/client3/web4 (/var/www/clients/client3/web4/.ssh/authorized_keys)
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the website-base dir directly.
        // What's most idiotic, is that it creates it even on shell_user operations...
        // ... that's why we need to reluctantly secure this file too (just in case),...
        // ... basically on any possible operation, in the Z-PLUGIN.
        $this->secure_ssh_directory($jail_root, false);
        
        $app->log('Z-PLUGIN: <<< "update_shell" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    function delete_shell($event_name, $data) {
        global $app;
        $app->log('Z-PLUGIN: --------- "delete_shell" - STARTED >>>', LOGLEVEL_DEBUG);
        $app->log("Z-PLUGIN: (delete_shell)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);
        
        $old_user = $data['old'];
        $jail_root = rtrim($old_user['dir'], '/');
        $domain_id = $old_user['parent_domain_id'];

        // Note: The "A" plugin has already unlocked the keys.
        // We only handle unmounting here if the jail becomes empty.

        if (is_dir($jail_root)) $app->system->exec_safe("chattr -i ?", $jail_root);
        
        // Refactored to use conditional logic (v19)
        // We pass true for $skip_lock because we are already unlocked in this block
        $this->manage_proc_and_devpts($jail_root, $domain_id, true);
        
        // Target: /var/www/clients/client3/web4 (/var/www/clients/client3/web4/.ssh/authorized_keys)
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the website-base dir directly.
        // What's most idiotic, is that it creates it even on shell_user operations...
        // ... that's why we need to reluctantly secure this file too (just in case),...
        // ... basically on any possible operation, in the Z-PLUGIN.
        $this->secure_ssh_directory($jail_root, false);
        
        //Non-chrooted and chrooted shell-users alike -> "delete-ONLY" operation
        //Always DELETE the shell_home_dir, because we don't want lingering unnecessary dirs on the OS filesystem, and the ISPConfig OOTB plugin, for some unknown reason isn't doing its job of deleting it...
        $shell_home_dir = rtrim($old_user['dir'], '/') . '/home/' . $old_user['username'];
        $app->system->exec_safe("rm -rf ?", $shell_home_dir);
        
        // Fail-safe Error Logging (v21)
        if ($app->system->last_exec_retcode() !== 0) {
            $app->log("Z-PLUGIN: \"$shell_home_dir\" rm -rf failed - shell-home-dir last resort deletion failed.", LOGLEVEL_ERROR);
        }
        
        //<---- Always DELETE the shell_home_dir -----------------------------------------------

        // Change #1: Reluctant and Safe Delete of "Vault/Backup" Directory
        // Logic: Delete ../webX___username
        $web_folder_name = basename($jail_root); // e.g., web12
        $client_dir = dirname($jail_root);       // e.g., /var/www/clients/client3
        
        // Construct the target directory path
        $vault_target_dir = $client_dir . '/' . $web_folder_name . '___' . $old_user['username'];

        // Safety Regex Check: Must match /var/www/clients/clientX/webX___
        if (preg_match('/^\/var\/www\/clients\/client\d+\/web\d+___/', $vault_target_dir)) {
            if (is_dir($vault_target_dir)) {
                $app->system->exec_safe("rm -rf ?", $vault_target_dir);
                // Silent fail requested: No logging if this fails or succeeds.
            }
        }
        
        if (is_dir($jail_root)) $app->system->exec_safe("chattr +i ?", $jail_root);
        
        $app->log('Z-PLUGIN: <<< "delete_shell" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    // --- WEBSITE USER LOGIC (web4) ---

    function update_web($event_name, $data) {
        global $app;
        $app->log('Z-PLUGIN: --------- "update_web" - STARTED >>>', LOGLEVEL_DEBUG);
        $app->log("Z-PLUGIN: Web Update Event: " . $event_name, LOGLEVEL_DEBUG);
        $app->log("Z-PLUGIN: (update_web)Full Data Payload: " . print_r($data, true), LOGLEVEL_DEBUG);
        
        $new_data = $data['new'];
        
        // Target: /var/www/clients/client3/web4/home/web4
        // ISPConfig creates this structure during 'web_domain_insert/update'
        $web_user_home = $new_data['document_root'] . '/home/' . $new_data['system_user'];
        
        // Ensure we wait for the directory to exist (it should, as Z runs last)
        if (is_dir($web_user_home)) {
            $this->secure_ssh_directory($web_user_home);
        } else {
             $app->log("Z-PLUGIN: Web user home not found (yet?): $web_user_home", LOGLEVEL_DEBUG);
        }
        
        // Target: /var/www/clients/client3/web4 (/var/www/clients/client3/web4/.ssh/authorized_keys)
        // ISPConfig sometimes (may be due to a bug) creates ".ssh/authorized_keys" in the "document_root" directly...
        // ... we need to secure this file also, just in case.
        $this->secure_ssh_directory($new_data['document_root'], false);
        
        // 2. Fix PHP-FPM Environment Variable
        if ($new_data['php'] == 'php-fpm') {
            $this->inject_custom_php_fpm_settings($new_data);
        }

        // 3. Manage Mounts (Check for changes in config or sections) (v19)
        $this->manage_proc_and_devpts($new_data['document_root'], $new_data['domain_id']);
        
        $app->log('Z-PLUGIN: <<< "update_web" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    function delete_web($event_name, $data) {
        global $app;
        $app->log('Z-PLUGIN: --------- "delete_web" - STARTED >>>', LOGLEVEL_DEBUG);
        
        // Since the DB record is likely already gone, we cannot check config.
        // We must perform an UNCONDITIONAL cleanup of mounts.
        // This ensures that if the Apache plugin failed to remove the directory 
        // (due to active mounts), we clean them up now.
        
        $old_data = $data['old'];
        $jail_root = $old_data['document_root'];
        
        if (is_dir($jail_root)) {
            // Unlock
            $app->system->exec_safe("chattr -i ?", $jail_root);
            
            // Force Unmount
            $this->remove_mounts($jail_root);
            
            // Cleanup "Zombie" directory if Apache plugin failed to remove it
            $app->system->exec_safe("rm -rf ?", $jail_root);
            
            // Fail-safe Error Logging (v21)
            if ($app->system->last_exec_retcode() !== 0) {
                $app->log("Z-PLUGIN: \"$jail_root\" rm -rf failed - website-root-dir last resort deletion failed.", LOGLEVEL_ERROR);
            }

            // Change #2: Safe Loop Delete for Associated Directories
            // Logic: Scan ../ for any directories matching webX___*
            
            $web_folder_name = basename($jail_root); // e.g. web12
            $client_dir = dirname($jail_root);       // e.g. /var/www/clients/client3

            if (is_dir($client_dir)) {
                $dir_contents = scandir($client_dir);
                if ($dir_contents !== false) {
                    foreach ($dir_contents as $item) {
                        if ($item == '.' || $item == '..') continue;

                        // Check if item name starts with "webX___"
                        if (strpos($item, $web_folder_name . '___') === 0) {
                            $full_item_path = $client_dir . '/' . $item;

                            if (is_dir($full_item_path)) {
                                // SAFETY: Strict PCRE check on the Absolute Path
                                if (preg_match('/^\/var\/www\/clients\/client\d+\/web\d+___/', $full_item_path)) {
                                    
                                    // Execute Safe Delete
                                    $app->system->exec_safe("rm -rf ?", $full_item_path);
                                    
                                    // Report if failed
                                    if ($app->system->last_exec_retcode() !== 0) {
                                        $app->log("Z-PLUGIN: Failed to remove associated directory: $full_item_path", LOGLEVEL_ERROR);
                                    } else {
                                        $app->log("Z-PLUGIN: Successfully removed associated directory: $full_item_path", LOGLEVEL_DEBUG);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            $app->log("Z-PLUGIN: Performed forced unmount and cleanup for deleted web: $jail_root", LOGLEVEL_DEBUG);
        }

        $app->log('Z-PLUGIN: <<< "delete_web" - COMPLETED ------', LOGLEVEL_DEBUG);
    }

    // --- PROVISIONING HELPER (New v22) ---
    private function execute_padm_provisioning($shell_user_data) {
        global $app;

        $script_path = '/usr/local/ispconfig/server/scripts/padm_shelluser_provision.sh';
        
        // 1. Validate Script Existence
        if (!file_exists($script_path)) {
            $app->log("Z-PLUGIN: Provisioning script not found at $script_path. Skipping.", LOGLEVEL_ERROR);
            return;
        }

        // 2. Fetch Dependent Data
        // Web Domain Data
        $web_domain = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $shell_user_data['parent_domain_id']);
        if (!$web_domain) {
            $app->log("Z-PLUGIN: Could not find web_domain for provisioning. Skipping.", LOGLEVEL_WARN);
            return;
        }

        // Client & Sys User Data
        $client_id = 0;
        if (preg_match('/^client(\d+)$/', $shell_user_data['pgroup'], $matches)) {
            $client_id = intval($matches[1]);
        } else {
             $app->log("Z-PLUGIN: Could not parse client_id from pgroup " . $shell_user_data['pgroup'] . ". Skipping provisioning.", LOGLEVEL_WARN);
             return;
        }

        $sys_user = $app->db->queryOneRecord('SELECT * FROM sys_user WHERE client_id = ?', $client_id);
        
        // 3. Determine Owner Details (Name & Email)
        $padm_owner_name = "";
        $padm_owner_email = "";

        if ($sys_user && $sys_user['typ'] == 'admin') {
            // ADMIN SCENARIO
            $app->uses('getconf');
            $global_mail_config = $app->getconf->get_global_config('mail');
            
            $padm_owner_name = isset($global_mail_config['admin_name']) ? $global_mail_config['admin_name'] : "Admin";
            $padm_owner_email = (isset($global_mail_config['admin_mail']) && $global_mail_config['admin_mail'] != "") ? $global_mail_config['admin_mail'] : "admin@hasnoemail.com";
        } else {
            // CLIENT SCENARIO
            $client_data = $app->db->queryOneRecord('SELECT * FROM client WHERE client_id = ?', $client_id);
            
            $padm_owner_name = isset($client_data['username']) ? $client_data['username'] : "Cname"; // Using username as requested
            $padm_owner_email = (isset($client_data['email']) && $client_data['email'] != "") ? $client_data['email'] : "client@hasnoemail.com";
        }

        // 4. Sanitize Owner Name (First word, Strict ASCII)
        // Get first word
        $name_parts = explode(' ', trim($padm_owner_name));
        $first_name = $name_parts[0];
        // Replace non-ASCII (non A-Z a-z) with 'X'
        $safe_owner_name = preg_replace('/[^a-zA-Z]/', 'X', $first_name);
        if (empty($safe_owner_name)) $safe_owner_name = "X"; // Fallback if name was only symbols

        // 5. Determine Server Name
        $app->uses('getconf');
        $server_config = $app->getconf->get_server_config($shell_user_data['server_id'], 'server');
        $hostname_full = $server_config['hostname'];
        // Get part before first dot
        $host_parts = explode('.', $hostname_full);
        $safe_server_name = $host_parts[0];
        if(empty($safe_server_name)) $safe_server_name = "myserver";

        // 6. Construct Arguments
        
        // ARG 1: <BASE_DIR>
        $arg_base_dir = $shell_user_data['dir'];

        // ARG 2: <SHELL_USER>
        $arg_shell_user = $shell_user_data['username'];

        // ARG 3: <SITE_NAME> (Uppercased first letter of domain)
        $arg_site_name = ucfirst($web_domain['domain']);

        // ARG 4: <EMAIL>
        // Format: [owner_email_prefix] + [site_name_lower] -on- [server_name_lower] @ [owner_email_suffix]
        $email_parts = explode('@', $padm_owner_email);
        $email_prefix = strtolower($email_parts[0]);
        $email_suffix = isset($email_parts[1]) ? strtolower($email_parts[1]) : "hasnoemail.com";
        $arg_email = $email_prefix . "+" . strtolower($arg_site_name) . "-on-" . strtolower($safe_server_name) . "@" . $email_suffix;

        // ARG 5: <FORGEJOGIT_USER>
        // Format: [owner_email_prefix] _ [site_name_lower_dots_to_underscore] _on_ [server_name_lower]
        $site_name_clean = str_replace('.', '_', strtolower($arg_site_name));
        $arg_forgejo_user = $email_prefix . "_" . $site_name_clean . "_on_" . strtolower($safe_server_name);

        // ARG 6: <FULLNAME>
        // Format: [OwnerName] at [SiteName] on [ServerName]
        // OwnerName and ServerName must have First Letter Uppercase, rest unchanged (from the sanitized versions)
        $owner_display = ucfirst($safe_owner_name);
        $server_display = ucfirst($safe_server_name);
        $arg_fullname = $owner_display . " at " . $arg_site_name . " on " . $server_display;

        // ARG 7: <CHROOT_CONFIG>
        $arg_chroot = $shell_user_data['chroot'];

        // 7. Execute Script
        $app->log("Z-PLUGIN: Executing Provisioning Script: $script_path", LOGLEVEL_DEBUG);
        
        // We use exec_safe with 8 placeholders (script path + 7 args)
        $app->system->exec_safe(
            "? ? ? ? ? ? ? ?", 
            $script_path, 
            $arg_base_dir, 
            $arg_shell_user, 
            $arg_site_name, 
            $arg_email, 
            $arg_forgejo_user, 
            $arg_fullname, 
            $arg_chroot
        );

        // 8. Log Output
        $output = $app->system->last_exec_out();
        $ret_code = $app->system->last_exec_retcode();
        
        // Collapse array output to string for logging
        $output_str = is_array($output) ? implode("\n", $output) : $output;
        
        if ($ret_code === 0) {
            $app->log("Z-PLUGIN: Provisioning Success. Output:\n" . $output_str, LOGLEVEL_DEBUG);
        } else {
            $app->log("Z-PLUGIN: Provisioning Failed (RetCode: $ret_code). Output:\n" . $output_str, LOGLEVEL_ERROR);
        }
    }


    // --- SECURITY & HELPERS ---

    // New Helper (v19): Conditional Mount Logic
    // Centralizes the logic for mounting/unmounting based on sections, php-fpm, and active users.
    private function manage_proc_and_devpts($jail_root, $domain_id, $skip_lock = false) {
        global $app;

        // 1. Get Current Website Settings from DB
        $web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
        
        // If web domain is missing (deleted?), we can't determine settings.
        // In update/insert events, it SHOULD exist. 
        if (!$web) {
            $app->log("Z-PLUGIN: Web domain ID $domain_id not found in DB. Skipping mount management.", LOGLEVEL_WARN);
            return; 
        }

        // 2. Get Server Jailkit Config
        $jailkit_conf = $app->getconf->get_server_config($web['server_id'], 'jailkit');

        // 3. Calculate Effective Sections
        // Logic mirrors apache2_plugin: Website setting overrides Server Config completely if set.
        $sections_str = $jailkit_conf['jailkit_chroot_app_sections'];
        if(isset($web['jailkit_chroot_app_sections']) && $web['jailkit_chroot_app_sections'] != '') {
            $sections_str = $web['jailkit_chroot_app_sections'];
        }
        
        // Split by space, comma, or newline
        $sections = preg_split('/[\s,]+/', $sections_str);
        $sections = array_map('trim', $sections);

        // Check for specific apps triggers
        $has_apps = (in_array('ps_top_w_uptime', $sections) || in_array('dtach', $sections));

        // 4. Check Activity Conditions
        $php_fpm_chrooted = (isset($web['php_fpm_chroot']) && $web['php_fpm_chroot'] == 'y');
        
        // Count active jailkit users (Reusing logic similar to is_jail_busy but without exclusion)
        $sql = "SELECT count(*) as c FROM shell_user WHERE parent_domain_id = ? AND chroot = 'jailkit'";
        $rec = $app->db->queryOneRecord($sql, $domain_id);
        $active_jail_users = intval($rec['c']);

        // 5. Evaluate Final Condition
        // IF ( (Appsections Present) AND ( (PHP-FPM Chrooted) OR (Jailed Shellusers Exist) ) )
        $should_mount = $has_apps && ($php_fpm_chrooted || $active_jail_users > 0);
        $app->log(("Z-PLUGIN: manage_proc_and_devpts cond: (<Appsections Present=".($has_apps?"true":"false")."> AND (<PHP-FPM Chrooted=".($php_fpm_chrooted?"true":"false")."> OR <Jailed Shellusers Exist=".(($active_jail_users > 0)?"true":"false").">)) => ensuring state ".($should_mount?"mounted":"U-mounted")), LOGLEVEL_DEBUG);

        // 6. Apply Action
        if ($should_mount) {
            // MOUNT
            if (!$skip_lock) $app->system->exec_safe("chattr -i ?", $jail_root);

            // /proc
            $proc_path = $jail_root . '/proc';
            $proc_fstab = "proc $proc_path none bind,nofail,hidepid=2,gid=procgroup 0 0";
            $proc_cmd = "mount --bind /proc ?"; 
            $this->ensure_mount($proc_path, $proc_fstab, $proc_cmd);

            // /dev/pts
            $pts_path = $jail_root . '/dev/pts';
            $pts_fstab = "devpts $pts_path devpts defaults,nofail,newinstance,nosuid,noexec,gid=5,mode=620 0 0";
            $pts_cmd = "mount -t devpts devpts ? -o defaults,newinstance,nosuid,noexec,gid=5,mode=620";
            $this->ensure_mount($pts_path, $pts_fstab, $pts_cmd);

            // /dev/ptmx
            $ptmx_path = $jail_root . '/dev/ptmx';
            if (!file_exists($ptmx_path)) {
                $app->system->exec_safe("mknod ? c 5 2", $ptmx_path);
                $app->system->exec_safe("chmod 666 ?", $ptmx_path);
            }

            if (!$skip_lock) $app->system->exec_safe("chattr +i ?", $jail_root);

        } else {
            // UNMOUNT
            if (!$skip_lock) $app->system->exec_safe("chattr -i ?", $jail_root);
            
            $this->remove_mounts($jail_root);
            
            if (!$skip_lock) $app->system->exec_safe("chattr +i ?", $jail_root);
        }
    }

    // Automatically inject env[HOME] into the PHP-FPM pool config
    // Replaced 'glob' with robust ISPConfig configuration lookups
    private function inject_custom_php_fpm_settings($web_data) {
        global $app, $conf;
        
        $system_user = $web_data['system_user'];
        
        // --------------------------------------------------------------------------------
        // 1. GENERATE SETTINGS CONTENT
        // --------------------------------------------------------------------------------
        $custom_settings = "";

        // Condition: Inject env[HOME] only if php_fpm_chroot is enabled
        if (isset($web_data['php_fpm_chroot']) && $web_data['php_fpm_chroot'] == 'y') {
            $custom_settings .= "\nenv[HOME] = /home/" . $system_user;
        }

        // You can add more 'if' blocks here in future to add other settings dynamically
        // if ($some_condition) { $custom_settings .= "\nsome_setting = value"; }


        // --------------------------------------------------------------------------------
        // 2. GUARD CLAUSE (Stop if nothing to add)
        // --------------------------------------------------------------------------------
        // If no settings were generated above, we stop here. 
        // No heavy code (DB lookups, File I/O, Service restarts) will execute.
        if (empty(trim($custom_settings))) {
            return;
        }


        // --------------------------------------------------------------------------------
        // 3. HEAVY LIFTING (Execute only if needed)
        // --------------------------------------------------------------------------------
        
        $server_id = $web_data['server_id'];
        $php_fpm_pool_dir = '';
        $init_script = '';
        $is_default_php = true;

        // Load web configuration to check for reload/restart preference
        $web_config = $app->getconf->get_server_config($server_id, 'web');

        // Determine the correct Pool Directory
        if($web_data['server_php_id'] != 0) {
            // Custom PHP Version
            $is_default_php = false;
            $server_php = $app->db->queryOneRecord('SELECT * FROM server_php WHERE server_php_id = ?', $web_data['server_php_id']);
            if($server_php) {
                $php_fpm_pool_dir = $server_php['php_fpm_pool_dir'];
                $init_script = $server_php['php_fpm_init_script'];
            }
        } else {
            // Default PHP Version (System Default)
            $php_fpm_pool_dir = $web_config['php_fpm_pool_dir'];
            $init_script = $web_config['php_fpm_init_script'];
        }

        if (empty($php_fpm_pool_dir)) {
            $app->log("Z-PLUGIN: Could not determine PHP-FPM pool directory for user: $system_user", LOGLEVEL_WARN);
            return;
        }

        // Construct the exact path (Same logic as apache2_plugin)
        $pool_file = $php_fpm_pool_dir . '/' . $system_user . '.conf';

        if (file_exists($pool_file)) {
            $content = $this->normalize_trailing_newlines(file_get_contents($pool_file));
            $update_required = false;
            
            // Universal update logic: 
            // We split our generated settings by newline and check each one individually.
            // This ensures we don't duplicate lines if one exists but another is missing.
            $lines_to_inject = explode("\n", trim($custom_settings));
            
            foreach($lines_to_inject as $line) {
                $line = trim($line);
                if(!empty($line) && strpos($content, $line) === false) {
                    // Append the missing line
                    $content .= "\n" . $line;
                    $update_required = true;
                    $app->log("Z-PLUGIN: Appending setting to PHP-FPM pool: $line", LOGLEVEL_DEBUG);
                } else {
                    $app->log("Z-PLUGIN: Skipping. In \"$pool_file\" there is already present: \"$line\"", LOGLEVEL_DEBUG);
                }
            }
            
            if ($update_required) {
                // Write back to file
                file_put_contents($pool_file, ($content."\n"));
                $app->log("Z-PLUGIN: Updated PHP-FPM pool file: $pool_file", LOGLEVEL_DEBUG);
                
                // Reload the correct PHP Service using OOTB method
                if(!empty($init_script)) {
                    $php_fpm_reload_mode = ($web_config['php_fpm_reload_mode'] == 'reload')?'reload':'restart';
                    
                    // Logic mirrored from apache2_plugin:
                    // If default PHP, we must prepend the init script path.
                    // If custom PHP, we usually get the full path or script name from DB.
                    if($is_default_php) {
                        $service_arg = $php_fpm_reload_mode . ':' . $conf['init_scripts'] . '/' . $init_script;
                    } else {
                        $service_arg = $php_fpm_reload_mode . ':' . $init_script;
                    }

                    $app->services->restartService('php-fpm', $service_arg);
                    $app->log("Z-PLUGIN: Triggered PHP-FPM service action ($php_fpm_reload_mode): $init_script", LOGLEVEL_DEBUG);
                }
            }
        } else {
            $app->log("Z-PLUGIN: PHP-FPM pool file not found at: $pool_file", LOGLEVEL_WARN);
        }
    }
    
    private function normalize_trailing_newlines(string $str): string {
        // Removes one or more spaces or tabs at the absolute end of the string
        $str = preg_replace('/[ \t]+$/', '', $str);

        // 1. Normalize all different types of newlines to a single format (e.g., LF) for consistency
        $str = str_replace(["\r\n", "\r"], "\n", $str);

        // 2. Globally replace one or more newlines at the end of the string with exactly one newline.
        $str = preg_replace('/\\n+$/', "\n", $str);

        //If there is NO new line at the end of the string -> add one
        if (substr($str, -1) !== "\n") {
            $str .= "\n";
        }

        return $str;
    }

    /**
    * $forceIt=true param ('true' is the default) signifies to ALWAYS create "$home_dir/.ssh/authorized_keys" dir-and-dummy-file (even if it does not exist).
    * While if it is explicitly set to 'false', then the function will perform a check if the file "$home_dir/.ssh/authorized_keys" already exists...
    * ... and if it doesen't -> it will basically do NOTHING. Will skip the whole locking (securing) procedure
    */
    private function secure_ssh_directory($home_dir, $forceIt = true) {
        global $app;
        
        if (!is_dir($home_dir)) return;

        $ssh_dir = $home_dir . '/.ssh';
        $key_file = $ssh_dir . '/authorized_keys';
        
        if (($forceIt === false) && (!file_exists($key_file))) {
            $app->log("Z-PLUGIN: Reluctantly tried to SECURE \"$key_file\", but there is no such file, so... skipping...", LOGLEVEL_DEBUG);
            return;
        }

        // 1. Create .ssh dir if missing (Crucial for 'web4' user which lacks it)
        if (!is_dir($ssh_dir)) {
            mkdir($ssh_dir, 0755, true);
            $app->log("Z-PLUGIN: Created missing .ssh dir: $ssh_dir", LOGLEVEL_DEBUG);
        }

        // 2. Lock .ssh dir ownership (Root:Root)
        $app->system->exec_safe("chown root:root ?", $ssh_dir);
        $app->system->exec_safe("chmod 755 ?", $ssh_dir);

        // 3. Create dummy authorized_keys if missing
        if (!file_exists($key_file)) {
            file_put_contents($key_file, "# Security Dummy File - Locked by Z-Plugin\n");
            $app->log("Z-PLUGIN: Created dummy keys: $key_file", LOGLEVEL_DEBUG);
        }

        // 4. LOCK the file (Root:Root + Immutable)
        $app->system->exec_safe("chown root:root ?", $key_file);
        $app->system->exec_safe("chmod 644 ?", $key_file);
        $app->system->exec_safe("chattr +i ?", $key_file);
        
        $app->log("Z-PLUGIN: SECURED (Immutable): $key_file", LOGLEVEL_DEBUG);
    }

    // Reusing is_jail_busy logic, but we don't need it inside manage_proc_and_devpts 
    // because we have direct count queries there. Keeping it if needed for other logic.
    private function is_jail_busy($dir, $exclude_user_id) {
        global $app;
        $sql = "SELECT count(*) as c FROM shell_user WHERE dir = ? AND chroot = 'jailkit' AND shell_user_id != ?";
        $rec = $app->db->queryOneRecord($sql, $dir, $exclude_user_id);
        return (intval($rec['c']) > 0);
    }

    private function ensure_mount($path, $fstab_line, $mount_cmd_template) {
        global $app;
        
        if (!is_dir($path)) $app->system->exec_safe("mkdir -p ?", $path);

        $fstab = file_get_contents('/etc/fstab');
        if (strpos($fstab, $path) === false) {
             $content_to_write = (substr($fstab, -1) !== "\n" ? "\n" : "") . $fstab_line . "\n";
             file_put_contents('/etc/fstab', $content_to_write, FILE_APPEND);
             $app->system->exec_safe("systemctl daemon-reload");
        }

        $is_mounted = false;
        // Refactored Mount Check using exec_safe
        $app->system->exec_safe("mount | grep ?", $path);
        $out_check = $app->system->last_exec_out();
        
        if (is_array($out_check) && count($out_check) > 0) $is_mounted = true;

        if (!$is_mounted) {
            // exec_safe fills the '?' in the template with the path
            $app->system->exec_safe($mount_cmd_template, $path);
        }
    }

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
        }
    }
}
?>
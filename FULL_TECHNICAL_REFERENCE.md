# Full Technical Reference & Architecture

This document provides a deep-dive into the architectural flow of the ISPConfig Advanced Jailkit Tools. It is intended for sysadmins and developers auditing the codebase.

### ⚠️ Architectural Assumptions & Compatibility Disclaimer
The core logic of these plugins and bash scripts relies heavily on strict regex parsing of ISPConfig's default directory paths. 
* **Target Paths:** The codebase exclusively targets the default structure: `^\/var\/www\/clients\/client\d+\/web\d+$`. 
* **Home Directories:** It also assumes the standard shell-account home-directory pattern (e.g., `.../webX/home/shell_user`). 
* **Consequence of Customization:** If a sysadmin has altered the default client/website directory patterns on the ISPConfig server filesystem via the UI, the provisioning scripts' safety checks and path resolutions will fail, leading to crashes or unpredictable security behaviors. This initial release does **not** support customized directory structures.

---

## 1. The PHP Plugins (Execution Flow)

The system utilizes two custom ISPConfig plugins to wrap around the default system behaviors: an "A" plugin (runs first) and a "Z" plugin (runs last).

### 1.1 The Immutability Matrix (`chattr +i` / `-i`)
The core security concept of the "Debian Fortress" relies on making critical files immutable (`chattr +i`). However, ISPConfig's native core plugins do not know about immutability. If ISPConfig tries to update or delete a locked file, it will crash or fail silently. 

Therefore, our plugins perform a carefully choreographed dance: the "A" plugin unlocks (`-i`) files *before* ISPConfig touches them, and the "Z" plugin locks (`+i`) them down *after* ISPConfig finishes.

**Target A: The SSH `authorized_keys` Files**
* **Paths Targeted:**
    * `/var/www/clients/clientX/webX/home/shu_username/.ssh/authorized_keys` (Standard Jailed/Shell Users)
    * `/var/www/clients/clientX/webX/home/webX/.ssh/authorized_keys` (The primary web user)
    * `/var/www/clients/clientX/webX/.ssh/authorized_keys` *(Bug Workaround: ISPConfig occasionally creates an `.ssh` directory directly in the document root during shell user operations. We target this path to be safe).*
* **Why Lock (`Z-Plugin`):** To prevent privilege escalation. Even if a website is compromised via a PHP vulnerability, the attacker cannot inject their own SSH key to establish a persistent backdoor. The keys are strictly read-only at the filesystem level.
* **Why Unlock (`A-Plugin`):** When an admin updates a user's SSH key in the ISPConfig UI, the core system attempts a standard `file_put_contents`. The A-Plugin must remove the immutable bit just in time for this write to succeed.

**Target B: The Website Root Directory (`$jail_root`)**
* **Paths Targeted:** `/var/www/clients/clientX/webX`
* **Why Lock/Unlock (`Z-Plugin & A-Plugin`):** 1.  **Mounting Operations:** The Z-Plugin dynamically binds `/proc` and `/dev/pts`. To ensure the mount/unmount commands do not fail due to directory restrictions, the Z-plugin temporarily unlocks the root directory, performs the mount, and locks it again.
    2.  **Teardown (`web_domain_delete`):** When a website is deleted, the standard Apache plugin attempts an `rm -rf` on the root. The A-Plugin must strip the immutable bit from the `$jail_root` so the directory can actually be purged, preventing "zombie" directories from cluttering the server.

### 1.2 Plugin Idempotency & State Management
Both plugins are designed to be completely **idempotent**. They are triggered on both `insert` (creation) and `update` (modification) events. Whether executed on a brand new shell-user or an existing one, the system guarantees safe operation without duplication:
* **Fstab & Mount Management:** The `ensure_mount` function reads `/etc/fstab` and actively runs `mount | grep` before executing. It will never create duplicate `fstab` entries or attempt to remount an already-mounted path.
* **PHP-FPM Config Injection:** The plugin reads the existing PHP-FPM `.conf` pool file. It parses the custom string (`env[HOME] = ...`) and only injects it if `strpos()` confirms it does not already exist, preventing config bloat on successive updates.

### 1.3 Smart Data Extraction & Identity Mapping (Z-Plugin)
Before the Z-Plugin triggers the bash provisioning engine, it queries the ISPConfig database (`web_domain` and `client` tables) to extract and construct context-aware arguments. This provides the user with a highly personalized and "ready-to-use" shell environment without requiring manual configuration:

* **Website Name (e.g., `Example.com`):** Extracted from the `domain` field of the `web_domain` table.
  * **Benefit:** Injected into the `_welcome.sh` UI and the custom `.bashrc` terminal prompt. When the user logs in, they are immediately greeted with the exact domain they are managing, providing instant context and preventing accidental operations on the wrong site.
* **Admin Email (e.g., `myname+example.com-on-myserver@email.com`):** Extracted from the `email` field of the `client` table. If the client has multiple comma-separated emails, the primary one is parsed.
  * **Benefit:** Injected directly into the generated `GITUSER.sh` configuration. This ensures that all Git commits made from this shell are automatically authored with a valid, associated email address, bypassing the need for manual `git config` setups.
* **Git User (e.g., `myname_example_com_on_myserver`):** Dynamically constructed by combining the client's username, the website domain, and the server hostname. It is then sanitized by replacing dots and hyphens with underscores.
  * **Benefit:** Creates a guaranteed unique, collision-free identifier across the infrastructure. The welcome screen presents this exact string to the user, telling them exactly what username they must create on the remote Git server for SSH authentication to succeed.
* **Full Name (e.g., `Myname at Example.com on Myserver`):** Constructed by combining the client's `contact_name`, the domain, and the server name into a human-readable format.
  * **Benefit:** Injected as the `user.name` variable in the Git configuration. This ensures that commits pushed to shared team repositories look highly professional, clearly identifying the exact author, website, and server environment originating the code.

### `plugins-available/a_chrooted_website_custom_func.inc.php` (Pre-Flight)
* **Goal:** Preparation and Error Prevention.
* **Immutability Bypass:** As detailed above, preemptively runs `chattr -i` on `.ssh/authorized_keys` and the jail root so standard ISPConfig operations do not crash.
* **Zombie Mount Prevention:** During a `web_domain_delete` event, it forcibly unmounts `/proc` and `/dev/pts` from the jail. If not done early, the core ISPConfig Apache plugin will fail to `rm -rf` the document root.

### `plugins-available/z_chrooted_website_custom_func.inc.php` (Post-Flight)
* **Goal:** Security Enforcement and Environment Provisioning.
* **Immutability Enforcement:** Re-applies `chattr +i` to critical directories and keys to prevent tampering.
* **Dynamic Mount Management:** Intelligently assesses if the jail needs `/proc` and `/dev/pts` based on PHP-FPM settings, active Jailkit users and activated `jk_init.ini` appsections. 
  * **`/proc` Security:** Mounts `/proc` securely using `hidepid=2` to ensure jailed users (and non-jailed users in that matter) cannot sniff or scrape the process arguments of other tenants on the server.
  * **`/dev/pts` Security:** Creates a highly secure pseudo-terminal environment. Instead of a standard bind mount, it uses the `newinstance` flag to generate a completely isolated, private PTY namespace for the jail (preventing host-terminal enumeration). It is further hardened with `nosuid` and `noexec` to prevent privilege escalation, while native kernel permissions (`mode=620`) prevent jailed users from hijacking each other's terminal streams. Mounts survive server restarts because they are safely and idempotently maintained in `/etc/fstab` by the plugin.
* **PHP-FPM Environment Injection:** Dynamically writes `env[HOME] = /home/webX` into the website's PHP-FPM pool configuration and safely reloads the service, enabling correct path resolution inside the chroot.
* **Triggering the Bash Engine:** Gathers domain, client, and server data from the database (as detailed in Section 1.3), sanitizes it, and passes it securely via `$app->system->exec_safe` to the main provisioning bash script.
* **Vault Cleanup:** On `web_domain_delete`, it safely hunts down and deletes the `webX___username` Vault directories.

## 2. The Bash Provisioning Engine (`padm_shelluser_provision.sh`)

This script runs as root and configures the actual OS-level user environment. 

> **Maintainability Note:** The current version of this script is battle-tested and fully functional, but it is difficult to maintain and extend due to its overall length and monolithic structure. To address this issue, an architectural refactoring is planned for the next release. See what refactoring steps are planned in the "6. Future Roadmap & Refactoring (TODOs for v2.0)" section below.

### The Provisioning Pipeline
To ensure idempotency and safe re-execution, the script is strictly chronological and executes in seven distinct phases:

* **PHASE 1: Initialization & Scenario Routing**
  Validates incoming ISPConfig arguments and determines the user's scenario (`1` = Jailed, `2` = Admin, `3` = Standard). Sets up core variables, colors, and extracts server/domain names.
* **PHASE 2: Vault Scaffolding (Admins & Standard Only)**
  Constructs the `webX___username` secure Vault outside the PHP-FPM chroot. Creates the hidden `.padm_git_resources` directories and strictly enforces `700` permissions.
* **PHASE 3: Helper Script Generation**
  Dynamically generates the user-facing `padm_` helper commands. This phase is broken down into three critical script generations, all designed with strict idempotency to protect user data:
  * **3.1 Generating `GITUSER.sh` (Identity & Configuration):** Creates a sourced configuration file defining the Git user's email, name, and `.gitignore` paths. 
    * *Why:* In a shared hosting environment, relying on global `~/.gitconfig` files is unreliable. This script explicitly binds the ISPConfig user's identity to their Git actions. 
    * *Idempotency:* It is wrapped in an `if [ ! -f ... ]` check. If the user edits this file to change their Git author name, subsequent runs of the provisioning script will safely skip generation, preserving their customizations.
  * **3.2 Generating `padm_activate_git` (Authentication & Environment):** Generates the script responsible for preparing the shell session for Git operations.
    * *Why:* It conditionally generates an `id_ed25519` SSH keypair and a custom SSH `config` file mapped specifically to the Git server. It also exports variables like `GIT_WORK_TREE` and `GIT_SSH_COMMAND`, allowing the user to run standard `git` commands without typing out long path arguments every time.
    * *Idempotency:* SSH keys and configs are only generated if they do not already exist, ensuring an admin's public key registered on the Git server is never accidentally overwritten.
  * **3.3 Generating `padm_clone_git_repo` (The Detached Cloning Engine):** Generates the script that handles the actual repository retrieval.
    * *Why:* Standard `git clone` refuses to execute into a directory that already contains files (ISPConfig often creates default `index.html` or `stats/` directories). This script employs a "Scorched Earth / Temporary Backup" methodology: it safely moves existing web files to a temporary hidden folder, executes a clean clone using `--separate-git-dir` to push the `.git` metadata into the secure Vault, and finally restores the original ISPConfig files back over the working tree.
* **PHASE 4: Landing Pad Lockdown & Sanitization**
  Enforces the "Debian Fortress" model. For non-jailed users, the script takes root ownership of the home directory, truncates `.bash_history`, and locks `.profile` and `.config` to trap the user in the secure ecosystem. All of these is done to prevent jailed PHP-FPM processes to read the bash commands and program data of the non-jailed users. And also to prevent them to inject malicious code in the startup configuration of the non-jailed users.
* **PHASE 5: Self-Documenting UI Generation**
  Generates the interactive welcome screens and sets up environment sourcing. This phase guarantees the terminal documentation always matches the actual helper scripts on the server.
  * **5.1 The Self-Documenting Engine (BASHDOC Parser):** Injects a bash function (`print_bashdocs`) that parses other `padm_` scripts for `#BEGIN-BASHDOC` blocks.
    * *Why:* It ensures the terminal help menu is never out of sync. It dynamically colorizes outputs and replaces variables like `PADM_SCRIPT_NAME` at runtime based on the actual script contents.
  * **5.2 Generating `_welcome.sh` (Scenario UI):** Creates the main login script tailored to the user's specific scenario.
    * *Why:* It prints a custom welcome message explaining the user's environment boundaries (Vault vs. Web root) and lists available commands, automatically changing the directory to the web root upon login.
    * *Idempotency:* It overwrites itself completely on every run. This ensures that if an admin's scenario changes or new tools are added, the UI strictly reflects the current server state.
  * **5.3 Generating `_sourced.sh` (The Loader):** Creates a simple wrapper script that sources `_welcome.sh`.
    * *Why:* It is designed to be safely sourced by the user's `.bashrc` or `.profile` upon interactive login.
    * *Idempotency:* Wrapped in a file-exists check. If it exists, it is skipped. This prevents breaking user-added logic if they modify this file later to load their own custom bash aliases or functions.
* **PHASE 6: Shell Configuration & Runtime Injection**
  Applies block-replacement to the user's `.bashrc` to inject custom terminal prompts, Git tracking, and secure environment paths.
  * **6.1 Dynamic Prompt Construction:** Constructs a heavily escaped bash string containing the custom colored terminal prompt (`PS1`).
    * *Why:* It injects a wrapper function `$(__padm_git_prompt)` that only executes the standard `__git_ps1` if the user is currently inside the bounds of the Apache document root, preventing Git errors from bleeding into standard jail operations.
  * **6.2 Scenario-Specific Routing (XDG & History):** Conditionally appends environment variables to the `.bashrc` payload based on the user scenario.
    * *Why:* For non-jailed Admin and Standard users, the actual home directory is locked down (immutable/root-owned). This logic forcefully redirects `HISTFILE`, `MYSQL_HISTFILE`, and all standard `XDG` paths (Config, Data, Cache) safely into the isolated Vault directory.
  * **6.3 Surgical Block Replacement (`sed`):** Applies the payload to the actual `.bashrc` file on disk.
    * *Why:* To maintain strict idempotency without destroying user customizations. It uses `sed` to locate and delete any lines between `# BEGIN-PADM-SECTION` and `# END-PADM-SECTION`, and then appends the newly generated block. This ensures updates apply cleanly, never duplicate lines, and leave any custom aliases the user added to the top of their `.bashrc` completely untouched.
* **PHASE 7: Final Permissions & Cleanup**
  Generates dummy history files to prevent initial login errors, enforces final strict permissions on the Vault, and outputs the success summary.

### Idempotency & Safe Re-Execution
Critical user-specific files—such as the `GITUSER.sh` config, generated SSH Keys (`id_ed25519`), and SSH Config files—are wrapped in `if [ ! -f ... ]` checks. Once generated, they are *never* overwritten by subsequent script runs, protecting the user's customized Git identity and keys.

### Git Provisioning & Vault Security Details
* **Self-Hosted Git IPs:** By default, `scripts/padm_shelluser_provision.sh` contains a hardcoded `PADM_GIT_SERVER_IP_ADDRESS`. For standard Git services (like GitHub or GitLab), this IP is completely ignored. However, if you are cloning from a private, self-hosted Git service that *lacks* a DNS hostname, you must update this variable with your Git server's IP, and then your remote repo URL will become `ssh://git@ForgejoGit/Myorg-Inc/my_php_website_project.git` - exactly as the provided examples on the out-of-the-box generated bash scripts. Ofcourse you may change `ForgejoGit` with anything you want (by modifying `[PIPELINE EXPLANATION: 3.2b]` at `scripts/padm_shelluser_provision.sh`).
* **SSH Protocol Preference:** We highly recommend cloning via `ssh://` rather than `https://`. The provisioning script makes this seamless by automatically generating secure SSH keys for the environment.
* **Identity Management:** Your Git identity (`user.name`, `user.email`) is automatically populated and managed from a single centralized file.
* **Vault Lockdown:** All generated SSH keys and Git configuration files are locked down with strict `x00` permissions (readable only by the owner). Because they are stored within the Vault directory (outside the chroot), they are mathematically unreachable from the jailed PHP-FPM environment.

## 3. Jailkit Configuration Enhancements (`jk_init.ini`)

Modifications to `etc/jailkit/jk_init.ini` enable complex software inside the minimal jail. **Critically, these changes are scattered throughout the file, not just appended to the end.**

* **Core Utility Upgrades for UI:** The `[terminfo]` and `[basicshell]` sections were heavily modified to explicitly include `/usr/bin/tput` and the necessary terminal database files. This ensures that even the most restricted Tier 1 user (`jk_lsh sftp coreutils basicshell`) receives the custom colored welcome prompts without errors.
* **SFTP Reliability:** The `[sftp]` section was updated with broader lib paths to guarantee SSH-based file transfers work flawlessly alongside the limited shell.
* **Custom `/opt` Integration:** The `[jre_headless___openjdk_8_zulu_ca]` section demonstrates mapping custom Java installations into the chroot.
* **The `[dtach]` Section:** Brings in the core binary and `libutil.so.1` alongside the custom wrappers.
* **Global Exclusions:** Aggressive paths like `/usr/lib/google-cloud-sdk` are explicitly excluded across basic profiles to prevent credential leakage in modern cloud environments.
* **The `[ps_top_w_uptime]` Appsection Limitations:** While this section successfully provisions `ps` and `top` (secured via our `/proc` bind mounts), the commands `w`, `who`, `ping`, and `traceroute` are intentionally non-functional in v1.0. Granting raw socket access (for `ping`) or reading system-wide utmp logs (for `w`/`who`) natively inside a shared chroot introduces unacceptable privilege escalation and data leakage risks. They will remain disabled until secure wrappers are built.

## 4. The `dtach` Session Wrappers

### `optional-dtach-wrappers/pattach`, `pdetachnow`, `pdetachable`
Standard `dtach` requires explicit socket paths, which gets messy in ISPConfig-created Jailed and non-Jailed shell-accounts. These wrappers automate socket management.

* **State Resolution:** They first check for an explicit `XDG_STATE_HOME`. If absent, they fall back to an ISPConfig-aware logic routine.
* **Missing `getent` Workaround:** Because minimal Jailkit environments often strip `getent`, the wrappers parse `/etc/passwd` directly via `grep` and `cut` to resolve the shared `webX` user's home directory.
* **Result:** All background session sockets are safely and invisibly routed to the user's `.pdtach` directory, keeping the environment clean.

## 5. Manual Host OS Configurations (Required)

Because the extension plugins strictly manage the *chroot* environment mounts, they intentionally avoid mutating the core Host OS configuration to prevent critical failures. **The sysadmin must complete these steps manually:**

### A. The `[ps_top_w_uptime]` Section & `procgroup`
This section allows jailed users to execute `ps` and `top`. To strictly enforce that users only see processes matching their own UID, the `plugins-available/z_chrooted_website_custom_func.inc.php` plugin dynamically bind-mounts `/proc` into the jails using `hidepid=2,gid=procgroup`.

For this mechanism to function securely at the Host OS level without blinding the native `root` user, you must do the following on the host:
1. `groupadd procgroup`
2. `usermod -aG procgroup root`
3. Edit `/etc/fstab` to ensure the primary system `/proc` mount enforces this whitelist globally:
   `proc /proc proc defaults,hidepid=2,gid=procgroup 0 0`
4. `mount -o remount /proc`

### B. Installing `dtach`
The `dtach` binary is required for the session wrappers but is not pre-installed on Debian 12/13. 
1. Build from source (recommended): Download from [https://github.com/crigler/dtach](https://github.com/crigler/dtach), run `./configure`, then `make`, and finally copy the binary: `cp dtach /usr/bin/`.
2. Alternatively, install via apt if available: `apt-get install dtach`.

---

## 6. Future Roadmap & Refactoring (TODOs for v2.0)

### 6.1 Addressing the Bloated Provisioning Script
To ensure the long-term maintainability of the bash provisioning engine (`scripts/padm_shelluser_provision.sh`) and to make it easier for the open-source community to contribute new `padm_` commands, we must address the script's monolithic size. The following architectural refactoring strategies are planned:

#### Strategy 1: Externalize the Heredocs (Templates)
Currently, a large percentage of the script's length comes from writing the text of other scripts (`_welcome.sh`, `padm_activate_git`, `.bashrc` injections) directly inside the main file using `cat <<EOF`. 
* **The Goal:** Move these raw scripts into a new `templates/` directory in the repository. The main script will use `envsubst` to inject variables into the templates at runtime. This will drastically shrink the main script and make it easier to edit helper scripts without navigating complex bash escaping logic.

#### Strategy 2: The "Drop-In" Directory Pattern
Adding a new `padm_` script currently requires modifying `if/then` blocks inside the main provisioner. 
* **The Goal:** Build a dynamic loader. We will create a directory structure like `src/payloads/all/`, `src/payloads/admin/`, and `src/payloads/jailed/`. The main provisioner will simply iterate through the appropriate directory based on the active scenario and deploy the scripts. This allows community members to drop new scripts into a folder and submit a Merge Request without touching the core provisioning logic.

#### Strategy 3: Separate Configuration from Logic
Variables like `PADM_GIT_SERVER_IP_ADDRESS` and the ANSI color codes are currently hardcoded at the top of the script.
* **The Goal:** Move these configurations into a `padm_config.env` file. This allows sysadmins to easily tweak terminal colors or default IPs without risking accidental breaks to the core bash logic.

### 6.2 Abstracting Path & Directory Assumptions (Dynamic Pathing)
The initial release relies on strict regular expressions hardcoded to the default ISPConfig directory structure (e.g., `^\/var\/www\/clients\/client\d+\/web\d+$`).
* **The Goal:** Refactor the "A" plugin, "Z" plugin, and the bash provisioning script to dynamically adapt to any filesystem configuration. This will involve querying ISPConfig's data or utilizing dynamic environment variables rather than hardcoded regex, allowing the extension to function flawlessly even if the sysadmin has customized the website root paths (e.g., `^\/clientsdata\/c\d+\/site\d+$`) or altered shell-user home directories via the ISPConfig UI.

### 6.3 Secure Network & User Wrappers (Completing `ps_top_w_uptime`)
To safely implement `ping`, `traceroute`, `w`, and `who` without compromising the chroot by granting raw `CAP_NET_RAW` capabilities or exposing host user data, we plan to build a client-server socket architecture. The jailed user will execute a dummy wrapper script inside the chroot. This wrapper will pipe the sanitized arguments over a socket to a root-owned daemon living *outside* the jail, which will safely execute the actual binary and pipe the `stdout` back to the user's terminal.

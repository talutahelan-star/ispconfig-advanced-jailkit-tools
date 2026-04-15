#!/bin/bash

# MIT License
# 
# Copyright (c) 2026 Talutah W Elan <talutahelan@gmail.com>
# 
# Git repo: https://github.com/talutahelan-star/ispconfig-advanced-jailkit-tools
# Discussion board: asd
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# ==============================================================================
# SCRIPT: padm_shelluser_provision.sh
# DESCRIPTION: Provisions a secure "Vault" environment for a non-chrooted
#              ISPConfig shell user, generating helper scripts for hidden Git management.
#              Handles Jailed, Admin, and Standard user scenarios dynamically.
# EXECUTION: Must be run as ROOT.
# ==============================================================================

# ==============================================================================
# PHASE 1: Initialization & Scenario Routing
# ==============================================================================

# ------------------------------------------------------------------------------
# 0. HARDCODED CONFIGURATION
# ------------------------------------------------------------------------------
# This IP will be injected into the generated scripts.
#
# 	Option 1 (for regular `ssh://` operations):
#		Leave empty ("") for universal Git SSH compatibility (ssh://git@GitHub, ssh://git@GitLab, ssh://git@Bitbucket, a self-hosted Git server with a DNS hostname, etc...)
#
# 	Option 2 (for dedicated private ISPConfig instances `ssh://` operations):
# 		Set an IP ONLY if using a self-hosted Git server without a DNS hostname, which you want to access by `ssh://`.
# 		If this is the case, then you may also change `GitServer` with anything you want (by modifying `[PIPELINE EXPLANATION: 3.2b]`
#
# Note: Choosing Option 2 will server-wide cripple the ability to clone via SSH from Git servers WITH a DNS hostname different than `GitServer`
# Note: Cloning via HTTPS has nothing to do with this setup here. It's completely independent, and will work either ways. There is no particular setup here, related to HTTPS-cloning.
# Note: But the user is completely on his own regarding the authorization with HTTPS. Public repos of course, do clone without authorization - out-of-the-box.
PADM_GIT_SERVER_IP_ADDRESS=""

# Color Codes Definition (tput commands injected into generated scripts)
# These are literal strings that will be written to the user scripts to be evaluated at runtime.
PADM_GEN_C_TITLES='$(tput setaf 2)'           # Green
PADM_GEN_C_ALLOTHER='$(tput setaf 15)'        # Bright White
PADM_GEN_C_EXAMPLE_COMMANDS='$(tput setaf 3)' # Yellow
PADM_GEN_C_PATH_DIRS='$(tput setaf 12)'       # Blue
PADM_GEN_C_PATH_FILES='$(tput setaf 6)'       # Cyan
PADM_GEN_C_RESET='$(tput sgr0)'               # Reset

# ------------------------------------------------------------------------------
# 1. ROOT CHECK
# ------------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# ------------------------------------------------------------------------------
# 2. ARGUMENT PARSING
# ------------------------------------------------------------------------------
PADM_CHROOT_BASE_DIR="$1"
PADM_SHELL_USERNAME="$2"
PADM_WEBSITE_NAME="$3"
PADM_WEBSITE_ADMIN_EMAIL="$4"
PADM_FORGEJO_USER="$5"
PADM_FORGEJO_USER_FULLNAME="$6"
PADM_CHROOT_CONFIG="$7"

if [[ -z "$PADM_CHROOT_BASE_DIR" || -z "$PADM_SHELL_USERNAME" || -z "$PADM_WEBSITE_NAME" || \
      -z "$PADM_WEBSITE_ADMIN_EMAIL" || -z "$PADM_FORGEJO_USER" || -z "$PADM_FORGEJO_USER_FULLNAME" || -z "$PADM_CHROOT_CONFIG" ]]; then
  echo "Error: Missing required arguments."
  
  cat <<MSG

  Usage:                    $0 \\
                            \\
                            <BASE_DIR> \\
                            <SHELL_USER> \\
                            <SITE_NAME> \\
                            <EMAIL> \\
                            <FORGEJOGIT_USER> \\
                            <FULLNAME> \\
                            <CHROOT_CONFIG> \\

  With sample data: $0 \\
                    \\
                    '/var/www/clients/client3/web12' \\
                    'shu_c3w12_admin' \\
                    'Example.com' \\
                    'myname+example.com-on-myserver@email.com' \\
                    'myname_example_com_on_myserver' \\
                    'Myname at Example.com on Myserver' \\
                    'none' \\

MSG
  exit 1
fi

# ------------------------------------------------------------------------------
# 3. VARIABLE INTERPOLATION & SCENARIO DETECTION
# ------------------------------------------------------------------------------

# Extract PADM_CLIENT_DIR: "/var/www/clients/client3/web2" -> "/var/www/clients/client3"
if [[ "$PADM_CHROOT_BASE_DIR" =~ ^(.+?)/web[0-9]+[[:space:]]*$ ]]; then
    PADM_CLIENT_DIR="${BASH_REMATCH[1]}"
else
    echo "Error: PADM_CHROOT_BASE_DIR does not match expected ISPConfig structure (.../web[n])."
    exit 1
fi

# Extract PADM_UID_USERNAME: "/var/www/clients/client3/web2" -> "web2"
if [[ "$PADM_CHROOT_BASE_DIR" =~ (web[0-9]+)[[:space:]]*$ ]]; then
    PADM_UID_USERNAME="${BASH_REMATCH[1]}"
else
    echo "Error: Could not extract web user (web[n]) from PADM_CHROOT_BASE_DIR."
    exit 1
fi

# Dynamically detect the Group ID from the '/web' subdirectory
if [ -d "${PADM_CHROOT_BASE_DIR}/web" ]; then
    PADM_UID_GROUP=$(stat -c '%G' "${PADM_CHROOT_BASE_DIR}/web")
else
    echo "Error: Web directory ${PADM_CHROOT_BASE_DIR}/web does not exist."
    exit 1
fi

PADM_TARGET_HOME="${PADM_CHROOT_BASE_DIR}/home/${PADM_SHELL_USERNAME}"

# --- DETERMINE SCENARIO ---
# Scenario 1: Jailed (jailkit)
# Scenario 2: Admin (Non-jailed + ends in _admin)
# Scenario 3: Standard (Non-jailed + NOT admin)

PADM_SCENARIO=0
PADM_SCENARIO_DESC=""

if [[ "$PADM_CHROOT_CONFIG" == "jailkit" ]]; then
    PADM_SCENARIO=1
    PADM_SCENARIO_DESC="Jailed (jailkit)"
else
    # Check if username ends in _admin (Case Insensitive)
    if [[ "${PADM_SHELL_USERNAME,,}" =~ _admin$ ]]; then
        PADM_SCENARIO=2
        PADM_SCENARIO_DESC="Admin (Non-jailed + ends in _admin)"
    else
        PADM_SCENARIO=3
        PADM_SCENARIO_DESC="Standard (Non-jailed + NOT admin)"
    fi
fi

# --- PATHS CONFIGURATION BASED ON SCENARIO ---
# PADM_SCRIPTS_DIR: Where the provisioner writes files (Root perspective)
# PADM_SCRIPTS_DIR_RUNTIME: Where the user accesses files (User perspective)

PADM_VAULT="${PADM_CLIENT_DIR}/${PADM_UID_USERNAME}___${PADM_SHELL_USERNAME}"
PADM_GIT_RES_DIR="${PADM_VAULT}/.padm_git_resources"

if [ $PADM_SCENARIO -eq 1 ]; then
    # Scenario 1: Jailed
    # Provisioning path inside the jail structure
    PADM_SCRIPTS_DIR="${PADM_TARGET_HOME}/padm_scripts"
    # Runtime path (absolute path inside the jail)
    PADM_SCRIPTS_DIR_RUNTIME="/home/${PADM_SHELL_USERNAME}/padm_scripts"
else
    # Scenario 2 & 3: Non-Jailed
    PADM_SCRIPTS_DIR="${PADM_VAULT}/padm_scripts"
    PADM_SCRIPTS_DIR_RUNTIME="${PADM_VAULT}/padm_scripts"
fi

echo "--- Configuration Detected ---"
echo "User:       $PADM_SHELL_USERNAME"
echo "Chroot:     $PADM_CHROOT_CONFIG"
echo "Scenario:   $PADM_SCENARIO - $PADM_SCENARIO_DESC"
echo "------------------------------"


# ==============================================================================
# PHASE 2: Vault Scaffolding (Admins & Standard Only)
# ==============================================================================

# ------------------------------------------------------------------------------
# 4. INITIALIZATION & VAULT SETUP
# ------------------------------------------------------------------------------

# Helper function for setting owner/perms idempotently
# Enforces ownership even if directory exists
ensure_dir() {
    local path="$1"
    local mode="$2"
    if [ ! -d "$path" ]; then
        mkdir -p "$path"
    fi
    chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$path"
    chmod "$mode" "$path"
    echo "   [+] Secured: $path"
}

if [ $PADM_SCENARIO -ne 1 ]; then
    echo "-> Step 1: Initializing Vault Structure..."
    # SCENARIO 2 & 3: Create Vault Base
    ensure_dir "$PADM_VAULT" "700"
    ensure_dir "$PADM_VAULT/.config" "700"
    ensure_dir "$PADM_VAULT/.local" "700" 
    ensure_dir "$PADM_VAULT/.local/share" "700"
    ensure_dir "$PADM_VAULT/.local/state" "700"
    ensure_dir "$PADM_VAULT/.cache" "700"
    ensure_dir "$PADM_SCRIPTS_DIR" "700" 

    if [ $PADM_SCENARIO -eq 2 ]; then
        echo "   [+] Initializing Git Resource directories (Admin Scenario)..."
        # SCENARIO 2 ONLY: Git Resources
        ensure_dir "$PADM_GIT_RES_DIR" "700"
        ensure_dir "$PADM_GIT_RES_DIR/ssh" "700"
        ensure_dir "$PADM_GIT_RES_DIR/repo" "700"
    fi
else
    echo "-> Step 1: Scenario 1 detected. Ensuring Jailed Scripts Dir."
    # SCENARIO 1: Just ensure the scripts dir exists inside the jail home
    ensure_dir "$PADM_SCRIPTS_DIR" "700"
fi

# ==============================================================================
# PHASE 3: Helper Script Generation
# ==============================================================================

# ------------------------------------------------------------------------------
# 5. GENERATE GITUSER.sh (Conditional Creation)
# ------------------------------------------------------------------------------

# [PIPELINE EXPLANATION: 3.1]
# We generate GITUSER.sh to explicitly define the user's Git identity (Name/Email)
# and global ignore rules. We do this because relying on a global ~/.gitconfig 
# in a shared/chrooted environment is unreliable. 
# IDEMPOTENCY: Wrapped in a file-exists check so if the user manually edits their 
# author name/email later, we never overwrite their customizations.

PADM_GITUSER_SCRIPT="${PADM_GIT_RES_DIR}/GITUSER.sh"

if [ $PADM_SCENARIO -eq 2 ]; then
    echo "-> Step 2: Checking/Generating GITUSER.sh..."
    if [ ! -f "$PADM_GITUSER_SCRIPT" ]; then
cat <<EOF > "$PADM_GITUSER_SCRIPT"
#!/bin/bash

################################# 1. Identity Variables ####################################

# Put your Git-user email here (if you don't want to use the default-generated one)
PADM_WEBSITE_ADMIN_EMAIL="$PADM_WEBSITE_ADMIN_EMAIL"

# Put your Git Server login username here
PADM_FORGEJO_USER="$PADM_FORGEJO_USER"

# Put your Full Name here (the way you want it displayed in commits by you)
PADM_FORGEJO_USER_FULLNAME="$PADM_FORGEJO_USER_FULLNAME"

###########################################################################################



# 2. Config Application (Only if HEAD exists = Valid Repo)
if [[ -f "\$GIT_DIR/HEAD" ]]; then
    # External Git Config logic sourced by activation script
    if [ -f "\$GIT_RES_DIR/gitignore.txt" ]; then
        git config --file "\$GIT_DIR/config" core.excludesFile "\$GIT_RES_DIR/gitignore.txt"
    fi

    # User Identity
    git config --file "\$GIT_DIR/config" user.name "\$PADM_FORGEJO_USER_FULLNAME"
    git config --file "\$GIT_DIR/config" user.email "\$PADM_WEBSITE_ADMIN_EMAIL"
fi
EOF
        chmod 700 "$PADM_GITUSER_SCRIPT"
        chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$PADM_GITUSER_SCRIPT"
        echo "   [+] Generated GITUSER.sh"
    else
        echo "   [.] GITUSER.sh already exists, skipping."
    fi
else
    echo "-> Step 2: Skipping GITUSER.sh (Not Admin Scenario)."
fi

# ------------------------------------------------------------------------------
# 6. GENERATE padm_activate_git (Overwrite)
# ------------------------------------------------------------------------------

# [PIPELINE EXPLANATION: 3.2]
# Generates the 'padm_activate_git' command. This script acts as the environment 
# bootstrap for the user. It provisions backend SSH authentication to the Git server
# and exports the GIT_WORK_TREE variables so the user doesn't have to pass 
# detached-path arguments manually to every git command.

SCRIPT_ACTIVATE="${PADM_SCRIPTS_DIR}/padm_activate_git"

if [ $PADM_SCENARIO -eq 2 ]; then
    echo "-> Step 3: Generating padm_activate_git..."
cat <<EOF > "$SCRIPT_ACTIVATE"
#!/bin/bash

#BEGIN-BASHDOC
# ➤ command 'PADM_SCRIPT_NAME'
#    Activates Git tracking on PADM_WEBSITE_WEB_DIR
#    Generates SSH key-pair if there isn't one already in .padm_git_resources/ssh
#    Generates an SSH config if there isn't one already in .padm_git_resources/ssh
#    
#    Example usage:
#     (begin-example)PADM_SCRIPT_NAME(end-example) (no arguments)
#END-BASHDOC

# HARDCODED VARIABLES (From Provisioning)
PADM_GIT_SERVER_IP_ADDRESS="$PADM_GIT_SERVER_IP_ADDRESS"
PADM_WEBSITE_NAME="$PADM_WEBSITE_NAME"
PADM_CHROOT_BASE_DIR="$PADM_CHROOT_BASE_DIR"

# DERIVED PATHS
PADM_VAULT="$PADM_VAULT"
PADM_GIT_RES_DIR="$PADM_GIT_RES_DIR"
PADM_GIT_DIR="\$PADM_GIT_RES_DIR/repo"
PROJECT_DIR="\$PADM_CHROOT_BASE_DIR/web"

# Helper function for setting owner/perms idempotently
ensure_dir() {
    local path="\$1"
    local mode="\$2"
    if [ ! -d "\$path" ]; then
        mkdir -p "\$path"
    fi
    chmod "\$mode" "\$path"
}
ensure_dir "\$PADM_GIT_RES_DIR/ssh" "700"

# Color Definitions
C_TITLES=${PADM_GEN_C_TITLES}
C_ALLOTHER=${PADM_GEN_C_ALLOTHER}
C_EXAMPLE_COMMANDS=${PADM_GEN_C_EXAMPLE_COMMANDS}
C_PATH_DIRS=${PADM_GEN_C_PATH_DIRS}
C_PATH_FILES=${PADM_GEN_C_PATH_FILES}
C_RESET=${PADM_GEN_C_RESET}

# SOURCE GITUSER (For Variables & Config)
# This provides: PADM_WEBSITE_ADMIN_EMAIL, PADM_FORGEJO_USER, PADM_FORGEJO_USER_FULLNAME
if [ -f "\$PADM_GIT_RES_DIR/GITUSER.sh" ]; then
    # Define exports needed for GITUSER's config logic, 
    # even if GITUSER checks for repo existence internally.
    export GIT_DIR="\$PADM_GIT_DIR"
    export GIT_RES_DIR="\$PADM_GIT_RES_DIR"
    
    source "\$PADM_GIT_RES_DIR/GITUSER.sh"
fi

# ------------------------------------------------------------------------------
# 1. SSH KEY GENERATION (Conditional)
# ------------------------------------------------------------------------------

# [PIPELINE EXPLANATION: 3.2a]
# Generates a secure ed25519 keypair specifically for SSH GitServer authentication.
# IDEMPOTENCY: We check if the key exists first. This guarantees that if the user 
# has already uploaded their public key to the remote Git server, running the 
# provisioner again won't destroy their backend access.

if [ ! -f "\$PADM_GIT_RES_DIR/ssh/id_ed25519" ]; then
    # PADM_FORGEJO_USER comes from sourced GITUSER.sh above
    ssh-keygen -t ed25519 -f "\$PADM_GIT_RES_DIR/ssh/id_ed25519" -C "\$PADM_FORGEJO_USER" -N "" -q
    chmod 600 "\$PADM_GIT_RES_DIR/ssh/id_ed25519"
    chmod 600 "\$PADM_GIT_RES_DIR/ssh/id_ed25519.pub"
    echo "   [+] Generated and secured new ssh/id_ed25519 and ssh/id_ed25519.pub"
fi

# ------------------------------------------------------------------------------
# 2. SSH CONFIG GENERATION (Conditional)
# ------------------------------------------------------------------------------

# [PIPELINE EXPLANATION: 3.2b]
# Creates a custom SSH config to map the 'GitServer' alias to the correct IP,
# system user ('git'), and the isolated IdentityFile. This bypasses the need 
# for a global ~/.ssh/config which might conflict with ISPConfig setups.

if [ ! -f "\$PADM_GIT_RES_DIR/ssh/config" ]; then
    if [ -n "\$PADM_GIT_SERVER_IP_ADDRESS" ]; then
        # LEGACY MODE: Specific IP-bound alias for self-hosted servers
cat <<SSH_CONF > "\$PADM_GIT_RES_DIR/ssh/config"
Host GitServer
    HostName \$PADM_GIT_SERVER_IP_ADDRESS
    User git
    IdentityFile \$PADM_GIT_RES_DIR/ssh/id_ed25519
    IdentitiesOnly yes
    UserKnownHostsFile \$PADM_GIT_RES_DIR/ssh/known_hosts
SSH_CONF
    else
        # UNIVERSAL MODE: Applies Vault identity to any Git provider (GitHub, GitLab, etc.)
cat <<SSH_CONF > "\$PADM_GIT_RES_DIR/ssh/config"
Host *
    IdentityFile \$PADM_GIT_RES_DIR/ssh/id_ed25519
    IdentitiesOnly yes
    UserKnownHostsFile \$PADM_GIT_RES_DIR/ssh/known_hosts
SSH_CONF
    fi
    
    chmod 600 "\$PADM_GIT_RES_DIR/ssh/config"
    echo "   [+] Generated and secured new ssh/config"
fi

# ------------------------------------------------------------------------------
# 3. AUXILIARY FILES & PERMISSIONS
# ------------------------------------------------------------------------------
if [ ! -f "\$PADM_GIT_RES_DIR/gitignore.txt" ]; then
    touch "\$PADM_GIT_RES_DIR/gitignore.txt"
    chmod 600 "\$PADM_GIT_RES_DIR/gitignore.txt"
fi

if [ ! -f "\$PADM_GIT_RES_DIR/ssh/known_hosts" ]; then
    touch "\$PADM_GIT_RES_DIR/ssh/known_hosts"
    chmod 600 "\$PADM_GIT_RES_DIR/ssh/known_hosts"
fi

# Enforce strict perms
chmod 600 "\$PADM_GIT_RES_DIR/ssh/config" 2>/dev/null
chmod 600 "\$PADM_GIT_RES_DIR/ssh/id_ed25519" 2>/dev/null
chmod 600 "\$PADM_GIT_RES_DIR/ssh/id_ed25519.pub" 2>/dev/null

# ------------------------------------------------------------------------------
# 4. EXPORT ENV VARS
# ------------------------------------------------------------------------------
# GIT_DIR is already exported above, but we re-export standard envs here for clarity
export GIT_WORK_TREE="\$PROJECT_DIR"
export GIT_SSH_COMMAND="ssh -F \$PADM_GIT_RES_DIR/ssh/config"
export VAULT_DIR="\$PADM_VAULT"

# ------------------------------------------------------------------------------
# 5. REPO CHECK & OUTPUT
# ------------------------------------------------------------------------------
# Check if repo metadata exists (Checking for HEAD ensures it's a valid repo)
if [ -f "\$PADM_GIT_DIR/HEAD" ]; then

    # a) GITUSER.sh was already sourced at the top.
    #    The config logic inside it ran automatically if HEAD existed.
    
    # b) Print Status Message
    CURRENT_REPO=""
    if [ -f "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt" ]; then
        CURRENT_REPO=\$(cat "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt")
    fi

    cat <<MSG

    Currently cloned remote-repo:
    \${C_ALLOTHER}\${CURRENT_REPO}\${C_RESET}

    For website \${C_TITLES}\$PADM_WEBSITE_NAME\${C_RESET}

    You can set/edit your external gitignore rules for this repo, in file:
    \${C_PATH_FILES}\$PADM_GIT_RES_DIR/gitignore.txt\${C_RESET}

    If you don$(printf "\x27")t change anything, your commits will be authored as:
    "\${C_TITLES}\$PADM_WEBSITE_ADMIN_EMAIL\${C_RESET}" <\${C_TITLES}\$PADM_FORGEJO_USER_FULLNAME\${C_RESET}>
    
    If you wanna change this, edit file:
    \${C_PATH_FILES}\$PADM_GIT_RES_DIR/GITUSER.sh\${C_RESET}

MSG

else
    # Repo not cloned yet
    PUBKEY=\$(cat "\$PADM_GIT_RES_DIR/ssh/id_ed25519.pub")
    
    cat <<MSG

    Welcome to website \${C_TITLES}\$PADM_WEBSITE_NAME\${C_RESET} admin-user git operations.
    Directory \${C_PATH_DIRS}\$PADM_VAULT\${C_RESET} is detached from
    the chroot of the website, yet it belongs to the same user which runs
    the Apache PHP-FPM process for this website. Despite that, if the website
    gets hacked, hackers will not be able to get to files in this directory.
    That is why we initiate the Git tracking from here. For security purposes!
    Please store the most-sensitive files -> only in this dir!
    
    
    Your SSH key-pair is currently residing in the following dir
    (you can replace it with other key-pair, if you wish):
    \${C_PATH_DIRS}\$PADM_GIT_RES_DIR/ssh\${C_RESET}
    (it is a newly-generated key-pair, this script has just generated it)
    
    You can use it to access git repositories using 'ssh://' (when logged-in
    into this "_admin" shell-account only please!)


    Currently there is no git repository cloned and there is no git-tracking on
    directory \${C_PATH_DIRS}\$PADM_CHROOT_BASE_DIR/web\${C_RESET} (which is your Apache webdir)

    If you want to clone a repo, use this example command:
       
            \${C_EXAMPLE_COMMANDS}padm_clone_git_repo ssh://git@GitServer/Myorg-Inc/my_php_website_project.git\${C_RESET}
    

    BEFORE PROCEEDING WITH CLONING:
    First, make sure your user (\${C_ALLOTHER}\$PADM_FORGEJO_USER\${C_RESET}) has
    access to the repo you want to clone in the target Git Server!

    With the current setting, you have to create user in GitServer with username:
            '\${C_ALLOTHER}\$PADM_FORGEJO_USER\${C_RESET}'
         
    ... and public key:
            '\${C_ALLOTHER}\${PUBKEY}\${C_RESET}'
    
    ... and give him permission to the repo you wanna clone!
    
    In case you wanna change your username, edit file:
    \${C_PATH_FILES}\$PADM_GIT_RES_DIR/GITUSER.sh\${C_RESET}
    ... if you wish, you can also change your SSH key(s) (as mentioned above)
    
    Perform your desired changes, and re-run \${C_EXAMPLE_COMMANDS}padm_activate_git\${C_RESET} until
    you$(printf "\x27")re satisfied with what is displayed here.
    
MSG

fi
EOF

    chmod 700 "$SCRIPT_ACTIVATE"
    chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$SCRIPT_ACTIVATE"
    echo "   [+] Generated padm_activate_git."
else
    echo "-> Step 3: Skipping padm_activate_git (Not Admin Scenario)."
fi

# ------------------------------------------------------------------------------
# 7. GENERATE padm_clone_git_repo (Overwrite)
# ------------------------------------------------------------------------------

# [PIPELINE EXPLANATION: 3.3]
# Generates the 'padm_clone_git_repo' command. Standard 'git clone' refuses to 
# run on non-empty directories (like a live ISPConfig web root). This script 
# contains the complex "Scorched Earth" workaround to safely bypass that limitation.

SCRIPT_CLONE="${PADM_SCRIPTS_DIR}/padm_clone_git_repo"

if [ $PADM_SCENARIO -eq 2 ]; then
    echo "-> Step 4: Generating padm_clone_git_repo..."
cat <<EOF > "$SCRIPT_CLONE"
#!/bin/bash

#BEGIN-BASHDOC
# ➤ command 'PADM_SCRIPT_NAME'
#    Clones locally a specific remote Git repository passed as an argument.
#    Clones into PADM_WEBSITE_WEB_DIR
#    If there is a repo that is already cloned there,
#     it will ask for replacement confirmation. This way
#     the script has the capability with only one command,
#     to get completely fresh, and potentially unconfigured-copy
#     of a website from its remote Git repo.
#
#    Example usage:
#     (begin-example)PADM_SCRIPT_NAME ssh://git@GitServer/Myorg-Inc/my_php_website_project.git(end-example)
#END-BASHDOC

# HARDCODED VARIABLES
PADM_WEBSITE_NAME="$PADM_WEBSITE_NAME"
PADM_CHROOT_BASE_DIR="$PADM_CHROOT_BASE_DIR"

# DERIVED PATHS
PADM_VAULT="$PADM_VAULT"
PADM_GIT_RES_DIR="$PADM_GIT_RES_DIR"
PADM_GIT_DIR="\$PADM_GIT_RES_DIR/repo"
PROJECT_DIR="\$PADM_CHROOT_BASE_DIR/web"
PADM_GIT_REPO="\$1"
PADM_SCRIPTS_DIR="$PADM_SCRIPTS_DIR_RUNTIME"

# Color Definitions
C_TITLES=${PADM_GEN_C_TITLES}
C_ALLOTHER=${PADM_GEN_C_ALLOTHER}
C_EXAMPLE_COMMANDS=${PADM_GEN_C_EXAMPLE_COMMANDS}
C_PATH_DIRS=${PADM_GEN_C_PATH_DIRS}
C_PATH_FILES=${PADM_GEN_C_PATH_FILES}
C_RESET=${PADM_GEN_C_RESET}

# ------------------------------------------------------------------------------
# 1. PRE-FLIGHT CHECKS
# ------------------------------------------------------------------------------
# Check Keys
if [[ ! -f "\$PADM_GIT_RES_DIR/ssh/id_ed25519" || ! -f "\$PADM_GIT_RES_DIR/ssh/id_ed25519.pub" || ! -f "\$PADM_GIT_RES_DIR/ssh/config" ]]; then
    cat <<MSG

    Obviously this is a new shell account!
    Maybe you CANNOT clone a git repo before you have generated your SSH keys,
    and before you have uploaded your public key for SSH access in you target Git Server?

    Run the following command to generate local SSH key-pair and SSH config - automatically:
	(later, you can replace them with other keys if you want)
       
            \${C_EXAMPLE_COMMANDS}padm_activate_git\${C_RESET}

MSG
    exit 1
fi

# Check Args
if [ -z "\$PADM_GIT_REPO" ]; then
    echo "Error: Missing argument. Usage: padm_clone_git_repo <REPO_URL>"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. SUBROUTINE: IF_THERE_ISNT (Perform Cloning)
# ------------------------------------------------------------------------------
perform_cloning_procedure() {
    
    # UNSET GIT ENVIRONMENT
    # We must clear these to prevent 'git clone' from thinking the current
    # directory is already a working tree based on the parent shell's state.
    unset GIT_DIR
    unset GIT_WORK_TREE
    unset GIT_INDEX_FILE

    # a) Create temp dir
    TIMESTAMP=\$(date +"%Y%m%d%H%M%S%3N")
    RANDOM_NUM=\$((1000 + RANDOM % 9000))
    TMP_PRESERVE_WEB="\$PADM_CHROOT_BASE_DIR/private/preserved-web-\${TIMESTAMP}-\${RANDOM_NUM}"
    mkdir -p "\$TMP_PRESERVE_WEB"
	
	# [PIPELINE EXPLANATION: 3.3a]
    # The "Scorched Earth" / Backup Protocol:
    # Because ISPConfig often places default index.html, robots.txt, or stats/ 
    # folders in the web root upon creation, standard 'git clone' will abort.
    # We temporarily move all existing files to a hidden backup directory,
    # perform a clean clone, and then restore the backed-up files OVER the clone.

    # b) Move existing files
    # We use find to avoid moving the temp dir itself if it was inside (it's in private, so safe, but good practice)
    # Moving content of /web to backup.
    # We check if empty to avoid errors.
    if [ -n "\$(ls -A "\$PROJECT_DIR" 2>/dev/null)" ]; then
        mv "\$PROJECT_DIR"/* "\$TMP_PRESERVE_WEB"/ 2>/dev/null
        mv "\$PROJECT_DIR"/.* "\$TMP_PRESERVE_WEB"/ 2>/dev/null
    fi

    # c) Clone logic
    
    # SAFETY REGEX CHECK BEFORE DELETING GIT DIR
    # Ensure PADM_GIT_DIR is actually a git-res-dir repo before we blow it away
    # Regex: /var/www/clients/clientN/webN___USER/.padm_git_resources/repo
    if [[ "\$PADM_GIT_DIR" =~ ^/var/www/clients/client[0-9]+/web[0-9]+___[a-zA-Z0-9_]+/\.padm_git_resources/repo$ ]]; then
        # Force remove existing metadata to allow fresh clone
        rm -rf "\$PADM_GIT_DIR"
    else
        echo "Safety Warning: PADM_GIT_DIR does not match expected pattern. Aborting cleanup to prevent data loss."
        # We don't exit here, we let git clone fail naturally if the dir exists, 
        # but we prevented a dangerous rm -rf.
    fi

    # SCORCHED EARTH POLICY: Ensure PROJECT_DIR is absolute 0-byte empty before clone
    # This prevents 'working tree already exists' errors if mv missed hidden files.
    if [ -d "\$PROJECT_DIR" ]; then
        find "\$PROJECT_DIR" -mindepth 1 -delete
    fi

    if git clone \\
      --separate-git-dir="\$PADM_GIT_DIR" \\
      -c core.sshCommand="ssh -F \$PADM_GIT_RES_DIR/ssh/config" \\
      "\$PADM_GIT_REPO" \\
      "\$PROJECT_DIR"; then
        
        CLONE_EXIT_CODE=0
    else
        CLONE_EXIT_CODE=\$?
    fi
    
    # Unconditional Permission Fix for Metadata
    if [ -d "\$PADM_GIT_DIR" ]; then
        chmod 700 "\$PADM_GIT_DIR" 2>/dev/null
    fi

    # Post-clone cleanup (Common)
    rm -f "\$PROJECT_DIR/.git" 2>/dev/null
    
    # ------------------
    # SUCCESS ACTIONS
    # ------------------
    if [ \$CLONE_EXIT_CODE -eq 0 ]; then
        if [ -f "\$PADM_GIT_RES_DIR/ssh/known_hosts" ]; then
            chmod 600 "\$PADM_GIT_RES_DIR/ssh/known_hosts"
        fi

        # d) Save repo info
        echo "\$PADM_GIT_REPO" > "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt"
        chmod 600 "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt"

        # e) Update _sourced.sh
        SOURCED_FILE="\$PADM_SCRIPTS_DIR/_sourced.sh"
        if [ -f "\$SOURCED_FILE" ]; then
            if ! grep -qF "source \$PADM_SCRIPTS_DIR/padm_activate_git" "\$SOURCED_FILE"; then
                echo "" >> "\$SOURCED_FILE"
                echo "source \$PADM_SCRIPTS_DIR/padm_activate_git" >> "\$SOURCED_FILE"
            fi
        fi
    fi

    # ------------------
    # RESTORATION (Common)
    # ------------------
    # e) Move preserved files back (Overwrite enabled)
    # This restores files from the backup. 
    # If clone succeeded: it merges original content over the cloned repo.
    # If clone failed: it restores original content to the empty dir.
    if [ -n "\$(ls -A "\$TMP_PRESERVE_WEB" 2>/dev/null)" ]; then
        # We copy back. 'cp -a' or 'mv -f'. User said "overwrite files by default".
        # We use mv -f to restore.
        mv -f "\$TMP_PRESERVE_WEB"/* "\$PROJECT_DIR"/ 2>/dev/null
        mv -f "\$TMP_PRESERVE_WEB"/.* "\$PROJECT_DIR"/ 2>/dev/null
    fi

    # f) Remove temp dir if empty
    rmdir "\$TMP_PRESERVE_WEB" 2>/dev/null
    
    # SAFETY REGEX CHECK BEFORE RECURSIVE DELETE
    # Ensure the directory strictly matches the expected pattern inside 'private/preserved-web-...'
    if [[ "\$TMP_PRESERVE_WEB" == "\$PADM_CHROOT_BASE_DIR/private/preserved-web-"* ]]; then
        # If not empty (hidden files issue?), force rm if strictly temp and path is safe
        rm -rf "\$TMP_PRESERVE_WEB"
    else
        echo "Safety Warning: Skipping deletion of \$TMP_PRESERVE_WEB because it does not match the expected pattern."
    fi

    # ------------------
    # MESSAGING
    # ------------------
    if [ \$CLONE_EXIT_CODE -eq 0 ]; then
        # g) Success Message
        cat <<MSG

    Just-cloned a new repo \${C_ALLOTHER}\$PADM_GIT_REPO\${C_RESET} ...
    ... to \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET}

    \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET} is now set to be tracked by Git.

    You can set/edit your external gitignore rules for this repo, in file:
    \${C_PATH_FILES}\$PADM_GIT_RES_DIR/gitignore.txt\${C_RESET}
    
    To activate your Git tracking execute the following command:

            \${C_EXAMPLE_COMMANDS}source padm_activate_git\${C_RESET}

    Execute the above command now, and then you are ready to go to
    directory \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET} and start executing
    regular Git commands on the repo.

MSG
    else
        # g) Failure Message
        cat <<MSG

    FAILURE cloning \${C_ALLOTHER}\$PADM_GIT_REPO\${C_RESET} ...
    ... to \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET}

    \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET} was restored to its original.

    See the message that 'git' returned to understand what is the issue, fix it,
    and retry the cloning.
    
MSG
        return \$CLONE_EXIT_CODE
    fi
}

# ------------------------------------------------------------------------------
# 3. EXISTING REPO CHECK
# ------------------------------------------------------------------------------
# Check if git metadata exists (Checking for HEAD ensures it's a valid repo)
if [ -f "\$PADM_GIT_DIR/HEAD" ]; then
    CURRENT_REPO=""
    if [ -f "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt" ]; then
        CURRENT_REPO=\$(cat "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt")
    fi

    cat <<MSG
    
    There is an already-cloned repo in \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET}
    It is: \${C_ALLOTHER}\${CURRENT_REPO}\${C_RESET}
    For website \${C_TITLES}$PADM_WEBSITE_NAME\${C_RESET}
      
    And you are about to replace it with:
    \${C_ALLOTHER}\$PADM_GIT_REPO\${C_RESET}
    

    Now choose option:

    > (option 1): Type "yes" if you want to CLONE THE REPO YOU JUST SPECIFIED
    ON TOP of what is currently in \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET} (to basically
    replace it).
    WARNING: During the process, all the contents of the already-cloned local repo and its
    metadata will be irreversibly deleted from disk!!!
    By doing this you will delete what is currently the working website, and
    re-clone it, thus getting an absolutely fresh, and potentionally unconfigured-copy
    from a remote Git repo.
    Directory \${C_PATH_DIRS}\$PROJECT_DIR\${C_RESET} will be left completely empty for a while

    > (option 2): Otherwise: Press Enter without typing anything, to CANCEL the operation
    and exit.

MSG
    
    read -r RESPONSE
    if [[ "\${RESPONSE,,}" == "yes" ]]; then
        # Safety Regex Checks before recursive delete
        # Must match: /var/www/clients/clientN/webN/web
        if [[ "\$PROJECT_DIR" =~ ^/var/www/clients/client[0-9]+/web[0-9]+/web$ ]]; then
            # Empty recursively
            find "\$PROJECT_DIR" -mindepth 1 -delete
        fi

        # Must match vault repo path
        # Regex: /var/www/clients/clientN/webN___USER/.padm_git_resources/repo
        if [[ "\$PADM_GIT_DIR" =~ ^/var/www/clients/client[0-9]+/web[0-9]+___[a-zA-Z0-9_]+/\.padm_git_resources/repo$ ]]; then
            find "\$PADM_GIT_DIR" -mindepth 1 -delete
        fi

        rm -f "\$PADM_GIT_RES_DIR/currently_cloned_repo.txt"
        
        # e) Update _sourced.sh (Remove auto-source since we just blew away the repo)
        SOURCED_FILE="\$PADM_SCRIPTS_DIR/_sourced.sh"
        if [ -f "\$SOURCED_FILE" ]; then
            # Remove line and empty lines if needed
            sed -i "\|source \$PADM_SCRIPTS_DIR/padm_activate_git|d" "\$SOURCED_FILE"
        fi
        
        # CALL PROCEDURE
        perform_cloning_procedure
    else
        exit 0
    fi
else
    # CALL PROCEDURE (No existing repo)
    perform_cloning_procedure
fi
EOF

    chmod 700 "$SCRIPT_CLONE"
    chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$SCRIPT_CLONE"
    echo "   [+] Generated padm_clone_git_repo."
else
    echo "-> Step 4: Skipping padm_clone_git_repo (Not Admin Scenario)."
fi

# ==============================================================================
# PHASE 4: Landing Pad Lockdown & Sanitization
# ==============================================================================

# ------------------------------------------------------------------------------
# 8. LANDING PAD MANAGEMENT (LOCK vs UNLOCK)
# ------------------------------------------------------------------------------
if [ $PADM_SCENARIO -eq 1 ]; then
    # SCENARIO 1: UNDO / UNLOCK
    echo "-> Step 5: Unlocking Landing Pad (Undo Security)..."
    
    if [ -d "$PADM_TARGET_HOME" ]; then
        echo "   [+] Recursively reverting ownership on $PADM_TARGET_HOME..."
        # Recursively give ownership back to user
        # Suppress errors (2>/dev/null) to handle immutable .ssh dir or other anomalies
        chown -R "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$PADM_TARGET_HOME" 2>/dev/null || true
        
        # Reset permissions to sensible defaults
        # Home dir: 750 (User RWX, Group RX)
        chmod 750 "$PADM_TARGET_HOME" 2>/dev/null || true
        
        # Common subdirs (ensure user can access them)
        for sub in .config .local .cache .ssh; do
            if [ -d "$PADM_TARGET_HOME/$sub" ]; then
                chmod -R 700 "$PADM_TARGET_HOME/$sub" 2>/dev/null || true
                chown -R "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$PADM_TARGET_HOME/$sub" 2>/dev/null || true
            fi
        done
        echo "   [+] Landing Pad Unlocked (Reverted to User ownership)."
    fi

else
    # SCENARIO 2 & 3: LOCK / SANITIZE
    echo "-> Step 5: Sanitizing Landing Pad (Lock Security)..."

    # Enforce Root ownership on Home Root
    if [ -d "$PADM_TARGET_HOME" ]; then
        chown root:"$PADM_UID_GROUP" "$PADM_TARGET_HOME"
        chmod 750 "$PADM_TARGET_HOME"
        echo "   [+] Home directory locked (Root owned, 750)."
    fi

    # A. Truncate old history
    if [ -f "$PADM_TARGET_HOME/.bash_history" ]; then
        truncate -s 0 "$PADM_TARGET_HOME/.bash_history" 2>/dev/null
        chown root:"$PADM_UID_GROUP" "$PADM_TARGET_HOME/.bash_history" 2>/dev/null
        chmod 640 "$PADM_TARGET_HOME/.bash_history" 2>/dev/null
        echo "   [+] Truncated and locked old .bash_history."
    fi

    # B. Lock Critical Files
    LOCK_FILES=(".profile" ".gitconfig" ".bash_logout" ".lesshst")
    for file in "${LOCK_FILES[@]}"; do
        if [ -f "$PADM_TARGET_HOME/$file" ]; then
            chown root:"$PADM_UID_GROUP" "$PADM_TARGET_HOME/$file" 2>/dev/null
            chmod 640 "$PADM_TARGET_HOME/$file" 2>/dev/null
            echo "   [+] Locked critical file: $file"
        fi
    done

    # C. Lock Sub-Directories
    LOCK_DIRS=(".bashrc.d" ".cache" ".config" ".local")
    for dir in "${LOCK_DIRS[@]}"; do
        if [ -d "$PADM_TARGET_HOME/$dir" ]; then
            chown -R root:"$PADM_UID_GROUP" "$PADM_TARGET_HOME/$dir" 2>/dev/null
            chmod -R 700 "$PADM_TARGET_HOME/$dir" 2>/dev/null
            echo "   [+] Locked directory structure: $dir (No Access)"
        fi
    done
fi

# ==============================================================================
# PHASE 5: Self-Documenting UI Generation
# ==============================================================================

# ------------------------------------------------------------------------------
# 9. GENERATE _welcome.sh & _sourced.sh (All Scenarios)
# ------------------------------------------------------------------------------
echo "-> Step 6: Generating Welcome & Sourced scripts..."

# Set paths and content based on scenario variables derived in Step 3
SCRIPT_WELCOME="${PADM_SCRIPTS_DIR}/_welcome.sh"
SCRIPT_SOURCED="${PADM_SCRIPTS_DIR}/_sourced.sh"

# [PIPELINE EXPLANATION: 5.1]
# We inject a parsing engine that reads the source code of other padm_ scripts 
# looking for #BEGIN-BASHDOC blocks. 
# WHY: This creates a self-documenting UI. If we add new helper scripts in the future, 
# we don't have to manually update the welcome message; the script builds its own help menu.
BASHDOC_PARSER_FUNC='
print_bashdocs() {
    local dir="$1"
    local web_dir="$2"
    
    # Iterate over executable files starting with padm_
    for f in "$dir"/padm_*; do
        if [ -f "$f" ] && [ -x "$f" ]; then
            local script_name=$(basename "$f")
            
            # Extract BEGIN-BASHDOC block, remove markers, remove leading #
            sed -n "/^#BEGIN-BASHDOC/,/^#END-BASHDOC/p" "$f" | sed "1d;\$d" | sed "s/^#//" | while IFS= read -r line; do
                # Replace Placeholders
                line="${line//PADM_SCRIPT_NAME/$script_name}"
                line="${line//PADM_WEBSITE_WEB_DIR/$web_dir}"
                
                # Colorize (begin-example)...(end-example) -> Yellow
                # We use simple sed replacement for the markers
                line=$(echo "$line" | sed "s/(begin-example)/${C_EXAMPLE_COMMANDS}/g")
                line=$(echo "$line" | sed "s/(end-example)/${C_RESET}/g")
                
                # Colorize paths (if PADM_WEBSITE_WEB_DIR was replaced)
                # We do a basic check: if line contains the web_dir value, colorize it
                line=$(echo "$line" | sed "s|${web_dir}|${C_PATH_DIRS}${web_dir}${C_RESET}|g")

                # Print with indent
                echo "    $line"
            done
            # Add spacing between scripts
            echo ""
        fi
    done
}
'

# [PIPELINE EXPLANATION: 5.2]
# Generates the dynamic login banner.
# IDEMPOTENCY: We intentionally OVERWRITE this file on every run. This ensures that 
# if a user's scenario changes (e.g., they are upgraded from Standard to Admin), 
# their welcome message and available command list are immediately updated to reflect reality.
cat <<EOF > "$SCRIPT_WELCOME"
#!/bin/bash

# Color Definitions
C_TITLES=${PADM_GEN_C_TITLES}
C_ALLOTHER=${PADM_GEN_C_ALLOTHER}
C_EXAMPLE_COMMANDS=${PADM_GEN_C_EXAMPLE_COMMANDS}
C_PATH_DIRS=${PADM_GEN_C_PATH_DIRS}
C_PATH_FILES=${PADM_GEN_C_PATH_FILES}
C_RESET=${PADM_GEN_C_RESET}

${BASHDOC_PARSER_FUNC}

# LOGICK SECTION
EOF

# Append Scenario-Specific Content to _welcome.sh
if [ $PADM_SCENARIO -eq 1 ]; then
    # SCENARIO 1: JAILED
    cat <<MSG >> "$SCRIPT_WELCOME"
echo ""
echo "    Welcome to website \${C_TITLES}$PADM_WEBSITE_NAME\${C_RESET} CHROOTED shell account."
echo ""
echo "    With this shell account you are sharing the same chroot with the PHP-FPM processes"
echo "    which execute the .php scripts of this website. You also have the same Linux UID as"
echo "    the UID which runs your website's PHP-FPM processes."
echo ""
echo "                your shell-user home dir is : \${C_PATH_DIRS}/home/${PADM_SHELL_USERNAME}\${C_RESET}"
echo "              PHP-FPM processes home dir is : \${C_PATH_DIRS}/home/${PADM_UID_USERNAME}\${C_RESET}"
echo "                website's Apache web dir is : \${C_PATH_DIRS}/web\${C_RESET}"
echo ""

# List padm_ commands
if ls "${PADM_SCRIPTS_DIR_RUNTIME}"/padm_* 1> /dev/null 2>&1; then
    echo "    You have the following \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} commands available for your type of shell account:"
    echo "    ------------------------------------------------------------------------------------"
    print_bashdocs "${PADM_SCRIPTS_DIR_RUNTIME}" "/web"
    echo "    Type \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} and press \"Tab\" twice to begin..."
    echo "    ------------------------------------------------------------------------------------"
    echo ""
fi

# Change Directory
cd /web
MSG

elif [ $PADM_SCENARIO -eq 2 ]; then
    # SCENARIO 2: ADMIN
    cat <<MSG >> "$SCRIPT_WELCOME"
echo ""
echo "    Welcome to website \${C_TITLES}$PADM_WEBSITE_NAME\${C_RESET} ADMIN shell-user operations."
echo ""
echo "    VAULT dir \${C_PATH_DIRS}$PADM_VAULT\${C_RESET} is outside the chroot"
echo "    of the website, and this website's PHP engine cannot reach it. Yet, it"
echo "    belongs to the same user which runs the Apache PHP-FPM process for this website."
echo "    Despite that, if the website gets hacked, hackers will not be able to get"
echo "    to files in this directory. That is why we run and store important background"
echo "    stuff in it. For security purposes!"
echo ""
echo "    Please store the most-sensitive files -> only in your VAULT dir!"
echo ""
echo "      your shell-user home dir is : \${C_PATH_DIRS}${PADM_TARGET_HOME}\${C_RESET}"
echo "                your VAULT dir is : \${C_PATH_DIRS}${PADM_VAULT}\${C_RESET}"
echo "    PHP-FPM processes home dir is : \${C_PATH_DIRS}${PADM_CHROOT_BASE_DIR}/home/${PADM_UID_USERNAME}\${C_RESET}"
echo "      website's Apache web dir is : \${C_PATH_DIRS}${PADM_CHROOT_BASE_DIR}/web\${C_RESET}"
echo ""

# List padm_ commands
if ls "${PADM_SCRIPTS_DIR_RUNTIME}"/padm_* 1> /dev/null 2>&1; then
    echo "    You have the following \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} commands available for your type of shell-user:"
    echo "    ------------------------------------------------------------------------------------"
    print_bashdocs "${PADM_SCRIPTS_DIR_RUNTIME}" "${PADM_CHROOT_BASE_DIR}/web"
    echo "    Type \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} and press \"Tab\" twice to begin..."
    echo "    ------------------------------------------------------------------------------------"
    echo ""
fi

# Change Directory
cd "${PADM_CHROOT_BASE_DIR}/web"
MSG

elif [ $PADM_SCENARIO -eq 3 ]; then
    # SCENARIO 3: STANDARD
    cat <<MSG >> "$SCRIPT_WELCOME"
echo ""
echo "    Welcome to website \${C_TITLES}$PADM_WEBSITE_NAME\${C_RESET} NON-CHROOTED shell account."
echo ""
echo "    VAULT dir \${C_PATH_DIRS}$PADM_VAULT\${C_RESET} is outside the chroot"
echo "    of the website, and this website's PHP engine cannot reach it. Yet, it"
echo "    belongs to the same user which runs the Apache PHP-FPM process for this website."
echo "    Despite that, if the website gets hacked, hackers will not be able to get"
echo "    to files in this directory. That is why we run and store important background"
echo "    stuff in it. For security purposes!"
echo ""
echo "    Please store the most-sensitive files -> only in your VAULT dir!"
echo ""
echo "      your shell-user home dir is : \${C_PATH_DIRS}${PADM_TARGET_HOME}\${C_RESET}"
echo "                your VAULT dir is : \${C_PATH_DIRS}${PADM_VAULT}\${C_RESET}"
echo "    PHP-FPM processes home dir is : \${C_PATH_DIRS}${PADM_CHROOT_BASE_DIR}/home/${PADM_UID_USERNAME}\${C_RESET}"
echo "      website's Apache web dir is : \${C_PATH_DIRS}${PADM_CHROOT_BASE_DIR}/web\${C_RESET}"
echo ""

# List padm_ commands
if ls "${PADM_SCRIPTS_DIR_RUNTIME}"/padm_* 1> /dev/null 2>&1; then
    echo "    You have the following \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} commands available for your type of shell-user:"
    echo "    ------------------------------------------------------------------------------------"
    print_bashdocs "${PADM_SCRIPTS_DIR_RUNTIME}" "${PADM_CHROOT_BASE_DIR}/web"
    echo "    Type \${C_EXAMPLE_COMMANDS}padm_\${C_RESET} and press \"Tab\" twice to begin..."
    echo "    ------------------------------------------------------------------------------------"
    echo ""
fi

# Change Directory
cd "${PADM_CHROOT_BASE_DIR}/web"
MSG
fi

# Finalize _welcome.sh
chmod 600 "$SCRIPT_WELCOME"
chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$SCRIPT_WELCOME"
echo "   [+] Generated _welcome.sh"

# 8.b Generate _sourced.sh (Conditional)
# [PIPELINE EXPLANATION: 5.3]
# Generates a lightweight wrapper that simply sources the welcome script.
# IDEMPOTENCY: We check if it exists first. This allows power users to append their 
# own custom logic, aliases, or environment variables to _sourced.sh without fear 
# that our provisioning script will delete their customizations later.
if [ ! -f "$SCRIPT_SOURCED" ]; then
    cat <<EOF > "$SCRIPT_SOURCED"
#!/bin/bash

# LOGICK SECTION
source ${PADM_SCRIPTS_DIR_RUNTIME}/_welcome.sh
EOF
    # Ensure trailing newline
    echo "" >> "$SCRIPT_SOURCED"
    
    chmod 600 "$SCRIPT_SOURCED"
    chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$SCRIPT_SOURCED"
    echo "   [+] Generated _sourced.sh"
else
    echo "   [.] _sourced.sh already exists, skipping."
fi

# ==============================================================================
# PHASE 6: Shell Configuration & Runtime Injection
# ==============================================================================

# ------------------------------------------------------------------------------
# 10. CONFIGURE .BASHRC (BLOCK REPLACEMENT)
# ------------------------------------------------------------------------------
PADM_BASHRC="${PADM_TARGET_HOME}/.bashrc"
echo "-> Step 7: Configuring .bashrc (Block Replacement)..."

# --- GENERATE LOCAL VARIABLES FOR .BASHRC INJECTION ---

# 1. Short User (Regex: shu_(.+?)\s*$)
_GEN_SHORT="$PADM_SHELL_USERNAME"
if [[ "$PADM_SHELL_USERNAME" =~ shu_(.+)[[:space:]]*$ ]]; then
    _GEN_SHORT="${BASH_REMATCH[1]}"
fi

# 2. LC Website
_GEN_SITE="${PADM_WEBSITE_NAME,,}"

# 3. Server Name (Regex: _on_([a-zA-Z-]+?)\s*$)
_GEN_SERVER="server"
if [[ "$PADM_FORGEJO_USER" =~ _on_([a-zA-Z-]+)[[:space:]]*$ ]]; then
    _GEN_SERVER="${BASH_REMATCH[1]}"
fi

# [PIPELINE EXPLANATION: 6.1]
# We construct a massive, heavily escaped bash string containing the custom 
# colored terminal prompt and the Git tracking wrapper. We do this as a string 
# variable first so we can conditionally append the XDG routing logic below 
# before writing anything to disk.

# --- START CONSTRUCTING CONTENT ---
PADM_CONTENT="# BEGIN-PADM-SECTION
# This is a custom section introduced in all ISPConfig shell-users .bashrc files by the \"padm_shelluser_provision.sh\" script.

# --- CUSTOM PROMPT & WINDOW TITLE ---
PADM_SHELLUSER_SHORT=\"${_GEN_SHORT}\"
PADM_WEBSITENAME_LC=\"${_GEN_SITE}\"
PADM_SERVERNAME_EXTRACTED=\"${_GEN_SERVER}\"

# ------------------------------------------------------------------
#  CUSTOM ADDITION: Git Prompt Integration
# ------------------------------------------------------------------

# 1. Attempt to load the Git prompt script
if [ -f /usr/lib/git-core/git-sh-prompt ]; then
    . /usr/lib/git-core/git-sh-prompt
fi

# 2. Wrapper function to constrain Git Prompt to the Work Tree
#    This protects jailed users and prevents global branch display
__padm_git_prompt() {
    if type -t __git_ps1 >/dev/null; then
        if [ -n \"\$GIT_WORK_TREE\" ]; then
            # Only display if current directory is inside the GIT_WORK_TREE
            if [[ \"\$PWD/\" == \"\$GIT_WORK_TREE/\"* ]]; then
                __git_ps1 \" (%s)\"
            fi
        else
            # Fallback for standard git directories if GIT_WORK_TREE isn't set
            __git_ps1 \" (%s)\"
        fi
    fi
}

# ------------------------------------------------------------------
#  CUSTOM ADDITION: Enforce Color Prompt & Re-evaluate PS1
# ------------------------------------------------------------------

# 1. Force 256-Color Mode (ADDED FIX)
#    If the terminal reports as standard xterm, upgrade it to xterm-256color
#    This ensures tput commands used later have full access to the palette.
if [ \"\$TERM\" = \"xterm\" ]; then
    export TERM=xterm-256color
fi

# 1. Force the color prompt (Functionally equivalent to uncommenting line 46)
force_color_prompt=yes

# 2. Re-run the capability check (Replicating logic from lines 49-57)
#    This ensures we don't break the terminal if it genuinely can't support color.
if [ -n \"\$force_color_prompt\" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        color_prompt=yes
    else
        color_prompt=
    fi
fi

# 3. Re-set the PS1 string (Replicating logic from lines 59-63, now with Git Integration)
#    This overrides the PS1 set by the default configuration above.
if [ \"\$color_prompt\" = yes ]; then
    # COLOR VERSION: Orange frames + Blue Path + Cyan Git Branch
    # Orange: 38;5;208 (256 color) | Dir Blue: 01;34
    PS1='\${debian_chroot:+(\$debian_chroot)}\[\033[38;5;208m\]╚═ '\"\${PADM_SHELLUSER_SHORT}@ \${PADM_WEBSITENAME_LC}@\${PADM_SERVERNAME_EXTRACTED}\"' ═╡\[\033[01;34m\]\w\[\033[38;5;208m\]╞════\[\033[01;36m\]\$(__padm_git_prompt)\[\033[00m\] 💲 \[\033[00m\]'
else
    # NON-COLOR VERSION: ASCII decoration + Plain Git Branch
    PS1='\${debian_chroot:+(\$debian_chroot)}╚═ '\"\${PADM_SHELLUSER_SHORT}@ \${PADM_WEBSITENAME_LC}@\${PADM_SERVERNAME_EXTRACTED}\"' ═╡\w╞════\$(__padm_git_prompt) 💲 '
fi

# 4. Re-apply Xterm Window Title logic (Replicating logic from lines 67-72)
#    Because we overwrote PS1 in step 3, we must re-prepend the window title codes
#    if the user is in an xterm/rxvt environment.
case \"\$TERM\" in
xterm*|rxvt*)
    # This sets the window title bar to match the prompt info
    PS1=\"\[\e]0;\${debian_chroot:+(\$debian_chroot)}\${PADM_SHELLUSER_SHORT}@ \${PADM_WEBSITENAME_LC}@\${PADM_SERVERNAME_EXTRACTED}: \w\a\]\$PS1\"
    ;;
*)
    ;;
esac

# 5. Cleanup (Replicating line 64)
unset color_prompt force_color_prompt
"

# [PIPELINE EXPLANATION: 6.2]
# For Non-Jailed users, the actual home directory is locked down (immutable/root-owned).
# Therefore, we MUST inject environment variables into their .bashrc that redirect 
# standard shell history, MySQL history, and all XDG paths (config/cache) safely 
# into their isolated Vault directory.

# --- APPEND SCENARIO SPECIFIC CONTENT ---
if [ $PADM_SCENARIO -eq 1 ]; then
    # SCENARIO 1: JAILED CONTENT
    # Path is /home/$USER/padm_scripts
    PADM_CONTENT="${PADM_CONTENT}
# --- SECURITY HARDENING & RUNTIME REDIRECTION ---

# 1. Add PADM Scripts to PATH (Convenience)
export PATH=\"\$PATH:${PADM_SCRIPTS_DIR_RUNTIME}\"

# 2. Interactive Shell Detection & Sourcing
if [[ \$- == *i* ]]; then
    if [ -f \"${PADM_SCRIPTS_DIR_RUNTIME}/_sourced.sh\" ]; then
        source \"${PADM_SCRIPTS_DIR_RUNTIME}/_sourced.sh\"
    fi
fi
# END-PADM-SECTION"

else
    # SCENARIO 2 & 3: FULL REDIRECTS CONTENT
    # Path is $VAULT_DIR/padm_scripts
    PADM_CONTENT="${PADM_CONTENT}
# --- SECURITY HARDENING & RUNTIME REDIRECTION ---

# 1. Define the Secure Vault Path
export VAULT_DIR=\"${PADM_VAULT}\"

# 2. Redirect Shell History
export HISTFILE=\"\$VAULT_DIR/.bash_history\"
export MYSQL_HISTFILE=\"\$VAULT_DIR/.mysql_history\"

# 3. Redirect \"XDG\" Standard Paths
export XDG_CONFIG_HOME=\"\$VAULT_DIR/.config\"
export XDG_DATA_HOME=\"\$VAULT_DIR/.local/share\"
export XDG_STATE_HOME=\"\$VAULT_DIR/.local/state\"
export XDG_CACHE_HOME=\"\$VAULT_DIR/.cache\"

# 4. Redirect Legacy Runtime Files
export LESSHISTFILE=\"\$VAULT_DIR/.lesshst\"
export VIMINFO=\"\$VAULT_DIR/.viminfo\"

# 5. Add PADM Scripts to PATH (Convenience)
export PATH=\"\$PATH:${PADM_SCRIPTS_DIR_RUNTIME}\"

# 6. Interactive Shell Detection & Sourcing
if [[ \$- == *i* ]]; then
    if [ -f \"${PADM_SCRIPTS_DIR_RUNTIME}/_sourced.sh\" ]; then
        source \"${PADM_SCRIPTS_DIR_RUNTIME}/_sourced.sh\"
    fi
fi
# END-PADM-SECTION"
fi

# Perform Block Replacement
if [ -f "$PADM_BASHRC" ]; then
	
	# [PIPELINE EXPLANATION: 6.3]
    # Surgical Block Replacement (Idempotency):
    # We never just echo to the bottom of the file, because multiple runs would 
    # create massive duplication. Instead, we use sed to hunt down our specific 
    # BEGIN/END markers, delete the old block, and append the fresh one. 
    # This leaves any custom aliases the user added to the top of their .bashrc completely intact.
	
    # 1. Delete existing block (if found) using sed
    # Matches any lines from BEGIN-PADM-SECTION to END-PADM-SECTION inclusive
    sed -i '/^# BEGIN-PADM-SECTION/,/^# END-PADM-SECTION/d' "$PADM_BASHRC"
    
    # 2. Append new block
    echo "$PADM_CONTENT" >> "$PADM_BASHRC"
    
    # 3. Fix Ownership (if not jailed)
    if [ $PADM_SCENARIO -ne 1 ]; then
        chown root:"$PADM_UID_GROUP" "$PADM_BASHRC"
        chmod 644 "$PADM_BASHRC"
    else
        # If jailed, ensure user owns it
        chown "${PADM_UID_USERNAME}:${PADM_UID_GROUP}" "$PADM_BASHRC"
    fi
    echo "   [+] Updated .bashrc (Block Replacement)."
fi

# ==============================================================================
# PHASE 7: Final Permissions & Cleanup
# ==============================================================================

# ------------------------------------------------------------------------------
# 11. FINAL PERMISSIONS & CLEANUP (Conditional)
# ------------------------------------------------------------------------------
if [ $PADM_SCENARIO -ne 1 ]; then
    echo "-> Step 8: Finalizing Permissions..."
    # Create dummy history files to prevent permission errors on first login
    runuser -u "$PADM_UID_USERNAME" -- touch "$PADM_VAULT/.bash_history"
    runuser -u "$PADM_UID_USERNAME" -- touch "$PADM_VAULT/.mysql_history"

    # Fix Vault History File Permissions (Strict 600)
    chmod 600 "$PADM_VAULT/.bash_history" 2>/dev/null
    chmod 600 "$PADM_VAULT/.mysql_history" 2>/dev/null
    echo "   [+] Vault history files secured."
fi

echo "============================================================"
echo "SUCCESS: PADM Provisioning Complete."
if [ $PADM_SCENARIO -ne 1 ]; then
    echo "Vault:   $PADM_VAULT"
    echo "Scripts: $PADM_SCRIPTS_DIR"
else
    echo "Mode:    Jailed/Undo (Vault Skipped)"
fi
echo "============================================================"

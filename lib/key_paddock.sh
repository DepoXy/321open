#!/bin/sh
# vim:tw=0:ts=2:sw=2:et:norl:ft=bash
# Author: Landon Bouma <https://tallybark.com/>
# Project: https://github.com/DepoXy/321open#👐
# License: MIT

# Copyright (c) © 2024 Landon Bouma. All Rights Reserved.

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

_keypaddock_source_deps () {
  local _321_root="${1:-$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")/..}"

  # Load: infuse_symlinks_paddock_gpg, remove_symlinks_paddock_gpg
  . "${_321_root}/lib/biblio-gpg"

  # Load: infuse_symlinks_paddock_ssh, remove_symlinks_paddock_ssh
  . "${_321_root}/lib/biblio-ssh"

  # Load: infuse_symlinks_paddock_home_subdir, remove_symlinks_paddock_home_subdir
  . "${_321_root}/lib/biblio.321"
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

ensure_key_paddock_exists () {
  if verify_key_paddock_repo_and_home_dir_symlinks; then

    return 0
  fi

  if ( create_key_paddock_repo "${ONEOPEN_KEYS_PADDOCK}" ); then
    notice "Keys paddocked: $(highlight "${ONEOPEN_KEYS_PADDOCK}")"
  else
    warn "ALERT: Paddock unfinished: $(highlight "${ONEOPEN_KEYS_PADDOCK}")"
  fi
}

verify_key_paddock_repo_and_home_dir_symlinks () {
  if false \
    || [ -z "${ONEOPEN_KEYS_PADDOCK}" ] \
    || [ -d "${ONEOPEN_KEYS_PADDOCK}/.git" ] \
  ; then

    return 0
  fi

  if true \
    && [ -h "${HOME}/.gnupg" ] \
    && [ -h "${HOME}/.ssh/config" ] \
    && [ -h "${HOME}/.password-store" ] \
  ; then

    return 0
  fi

  return 1
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

ensure_key_paddock_symlinks () {
  # Create/Verify ~/.gnupg symlink
  infuse_symlinks_paddock_gpg
  # Create/Verify ~/.password-store symlink
  infuse_symlinks_paddock_pwd
  # Create/Verify ~/.ssh/id_* symlinks
  infuse_symlinks_paddock_ssh

  ! ${_321_VERBOSE_BLANKS:-false} || echo
}

# ***

remove_key_paddock_symlinks () {
  remove_symlinks_paddock_gpg
  remove_symlinks_paddock_pwd
  remove_symlinks_paddock_ssh
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

create_key_paddock_repo () {
  mkdir -p -- "${ONEOPEN_KEYS_PADDOCK}"

  # For SSH to work, parent of ~/.ssh much be restricted.
  chmod 700 "${ONEOPEN_KEYS_PADDOCK}"

  cd "${ONEOPEN_KEYS_PADDOCK}"

  git init -q -b private .

  git commit -q --allow-empty \
    -m "${ONEOPEN_PADDOCK_PROLOGUE:-y͟o͟u͟ ͟c͟a͟n͟n͟o͟t͟ ͟s͟h͟a͟k͟e͟ ͟h͟a͟n͟d͟s͟ ͟w͟i͟t͟h͟ ͟a͟ ͟c͟l͟e͟n͟c͟h͟e͟d͟ ͟f͟i͟s͟t͟}"

  prepare_keys_paddock_exclude

  relocate_keys_paddock_dirs

  ensure_keys_paddock_password_store
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

prepare_keys_paddock_exclude () {
  print_keys_paddock_exclude_gpg >> ".gitignore"

  echo >> ".gitignore"
  print_keys_paddock_exclude_ssh >> ".gitignore"

  echo >> ".gitignore"
  print_keys_paddock_exclude_pwd >> ".gitignore"

  # ***

  git add ".gitignore"

  git commit -q -m "Update: Add exclude rules"
}

# REFER: Concise explainer on GPG files:
# https://www.howtogeek.com/816878/how-to-back-up-and-restore-gpg-keys-on-linux/

print_keys_paddock_exclude_gpg () {
  cat <<'EOF'
# *** ~/.gnupg

# E.g., '.#lk0x0000600000648200.host.25060'
/.gnupg/.#lk0x*

/.gnupg/.gpg-connect_history

# Sockets
/.gnupg/S.gpg-agent*

# INCL.: .gnupg/openpgp-revocs.d/*.rev
# INCL.: .gnupg/private-keys-v1.d/*.key

# E.g., '.#lk0x0000000150f05c30.host.53147'
/.gnupg/public-keys.d/.#lk0x*
/.gnupg/public-keys.d/pubring.db.lock

# INCL.: .gnupg/pubring.kbx

/.gnupg/pubring.kbx~

/.gnupg/random_seed

# INCL.: .gnupg/sshcontrol
# INCL.: .gnupg/trustdb.gpg
EOF
}

print_keys_paddock_exclude_ssh () {
  cat <<'EOF'
# *** ~/.ssh

# INCL.: .ssh/authorized_keys
# INCL.: .ssh/config

/.ssh/environment

# INCL.: .ssh/id_*

/.ssh/known_hosts
/.ssh/known_hosts.old
EOF
}

print_keys_paddock_exclude_pwd () {
  cat <<'EOF'
# *** ~/.password-store

# `pass` maintains its own Git repo.
/.password-store/
EOF
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

relocate_keys_paddock_dirs () {
  relocate_keys_paddock_gnupg
  relocate_keys_paddock_pwds
  relocate_keys_paddock_ssh
}

# ***

relocate_keys_paddock_gnupg () {
  cd "${ONEOPEN_KEYS_PADDOCK}"

  local dir_name=".gnupg"

  local home_dir="${HOME}/${dir_name}"

  if true \
    && [ -d "${home_dir}" ] \
    && ! [ -h "${home_dir}" ] \
    && ! [ -d "${dir_name}" ] \
  ; then
    # Ignore ~/.gnupg sockets (e.g., ~.gnupg/S.gpg-agent, etc.)
    # to avoid cannot-move-socket errors.
    #
    # - Ideally, we'd use Bash v4+ process substitution, e.g.,
    #
    #     command mv -- "${home_dir}" "." 2> >(grep -v "${pattern}" >&2)
    #
    #   But so that OMR config can source this file, keep it POSIX.
    #
    #   - Note this means that STDOUT is redirected to STDERR, but
    #     there should be not STDOUT, either.
    local pattern="^cp: /Users/${LOGNAME}/.gnupg/S\.[^ ]\+ is a socket (not copied)."

    command mv -- "${home_dir}" "." 3>&1 1>&2 2>&3 3>&- \
      | grep -v "${pattern}" 3>&1 1>&2 2>&3 3>&-

    # ***

    command ln -sfn "${ONEOPEN_KEYS_PADDOCK}/${dir_name}" "${home_dir}"

    gpg_reload_agent

    # ***

    git add "."

    git commit -q -m "Insert: ${dir_name}/"
  fi
}

# ***

relocate_keys_paddock_pwds () {
  cd "${ONEOPEN_KEYS_PADDOCK}"

  local dir_name=".password-store"

  local home_dir="${HOME}/${dir_name}"

  if true \
    && [ -d "${home_dir}" ] \
    && ! [ -h "${home_dir}" ] \
    && ! [ -d "${dir_name}" ] \
  ; then
    command mv -- "${home_dir}" "."

    command ln -sfn "${ONEOPEN_KEYS_PADDOCK}/${dir_name}" "${home_dir}"

    # `pass` manages ~/.password-store Git repo, so Paddock
    # excludes it; therefore nothing to add and commit.
  fi
}

# ***

relocate_keys_paddock_ssh () {
  cd "${ONEOPEN_KEYS_PADDOCK}"

  local dir_name=".ssh"

  local home_dir="${HOME}/${dir_name}"

  mkdir -p -- "${dir_name}"

  # USYNC: Move same items that `infuse_symlinks_paddock_ssh` infuses.
  # - I.e., ~/.ssh/config and ~/.ssh/id_*
  #
  # This leaves authorized_keys behind, so you can logon when paddock
  # offline. We also leave known_hosts (and known_hosts.old), which we
  # don't need to backup or sync between hosts.

  find "${home_dir}" \
    -maxdepth 1 \
    -type f \
    -a \( -name config -o -name id_* \) \
    -exec mv -- "{}" "${dir_name}/." \;

  # ***

  git add "."

  git commit -q -m "Insert: ${dir_name}/ config &/or id_* keys" > /dev/null

  # ***

  # Note the ~/.ssh is *not* converted to a symlink, so that
  # we can persist ~/.ssh/authorized_keys for remote access
  # (so you can remote-in without Key Paddock being online).
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

ensure_keys_paddock_password_store () {
  local pwds_name=".password-store"

  cd "${ONEOPEN_KEYS_PADDOCK}"

  if [ -d "${pwds_name}/.git" ]; then

    return 0
  elif [ -z "${ONEOPEN_PASSWORD_STORE_EMAIL}" ]; then
    debug "SKIPD: Skipping ~/.password-store [set ONEOPEN_PASSWORD_STORE_EMAIL to use]"

    return 0
  fi

  # ***

  mkdir -p -- "${pwds_name}"

  command ln -sfn "${ONEOPEN_KEYS_PADDOCK}/${pwds_name}" "${HOME}/${pwds_name}"

  local PSTORE_KEYID
  find_or_generate_password_store_key_and_print_key_id \
    || return 1

  # Commit the new GPG key, maybe.
  if [ -n "$(git status --porcelain=v1)" ]; then
    git add "."

    git commit -q -m "Insert: Password Store key"
  fi

  # ***

  local output=""
  # Use the key to initialize `~/.password-store/.gpg-id`
  output="$(pass init "${PSTORE_KEYID}")"

  echo "${output}" | grep -v "^Password store initialized for .*" \
    || true

  # `pass git init -q` doesn't work here, b/c pass calls git-commit w/out -q.
  pass git init > /dev/null
}

# ***

find_or_generate_password_store_key_and_print_key_id () {
  local key_ids
  key_ids=$(print_password_store_key_ids)

  local match_cnt=0
  if [ -n "${key_ids}" ]; then
    match_cnt=$(echo "${key_ids}" | wc -l)
  fi

  if [ ${match_cnt} -gt 1 ]; then
    >&2 warn "ERROR: Cannot setup ~/.password-store"
    >&2 warn "- More than one GPG found for email: ${ONEOPEN_PASSWORD_STORE_EMAIL}"

    return 1
  fi

  if [ -z "${key_ids}" ]; then
    local passphrase="${PREVALENT_PHRASE}"

    if [ -z "${passphrase}" ]; then
      if ! ${USE_PREVALENT_PHRASE:-true}; then
        # User ran, e.g., `USE_PREVALENT_PHRASE=false 321open`
        # so ask for *just* this op, then forget the arg.
        local PREVALENT_PHRASE

        prompt_passphrase

        passphrase="${PREVALENT_PHRASE}"
      else
        >&2 error "GAFFE: Missing environ arg: PREVALENT_PHRASE" \
          "[find_or_generate_password_store_key_and_print_key_id]"

        return 1
      fi
    fi

    if ! _PRINT_TRACE=false generate_password_store_key "${passphrase}" 2>/dev/null; then
      >&2 warn "ERROR: Cannot setup ~/.password-store"
      >&2 warn "- \`gpg --full-generate-key ...\` failed:"
      >&2 echo
      _FAILURE_EXPECTED=true generate_password_store_key "${passphrase}" 2>&1 \
        | >&2 sed 's/^/  /' \
        || true
      >&2 echo

      return 1
    fi

    # Get the new KeyID.
    key_ids=$(print_password_store_key_ids)
  fi

  if [ -z "${key_ids}" ]; then
    # Lest:
    #   Error: /Users/user/.password-store//.gpg-id does not exist and so cannot be removed.
    >&2 error "GAFFE: Could not locate new Password Store GPG Key ID"

    exit_1
  fi

  PSTORE_KEYID="${key_ids}"
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

# Generate a new key — manually:
#
#   $ gpg --full-generate-key
#
#   Please select what kind of key you want:
#      (9) ECC (sign and encrypt) *default*
#
#   Please select which elliptic curve you want:
#      (1) Curve 25519 *default*
#
#   Please specify how long the key should be valid.
#            0 = key does not expire
#
#   Is this correct? (y/N) y
#
#   Real name: PasswordStore
#   Email address: PasswordStore@foo
#   Comment:
#   You selected this USER-ID:
#       "PasswordStore <PasswordStore@foo>"
#
#   Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
#
#   <Enter PWD twice>

# The `man gpg` example (at the bottom) fails:
#   $ gpg ... <<EOF
#     Key-Type: default
#     Subkey-Type: default
#     ...
#   EOF
#   gpg: key generation failed: Unknown elliptic curve
# - The following fix was found here:
#   https://lists.gnupg.org/pipermail/gnupg-users/2017-December/059619.html
# - See also:
#   https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html

generate_password_store_key () {
  local passphrase="$1"

  # Some other options:
  #  Name-Real:
  #  Name-Comment:

  # If an argument is missing, gpg errors, e.g.,:
  #   gpg: Generating a default key
  #   gpg: -:10: missing argument
  # Where -:10: is the line number of the parameters.

  local unattended_key_generation_parameters
  read -r -d '' unattended_key_generation_parameters <<EOF
%echo Generating a default key
Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
Name-Email: ${ONEOPEN_PASSWORD_STORE_EMAIL}
Expire-Date: 0
Passphrase: ${passphrase}
# Do a commit here, so that we can later print "done" :-)
%commit
%echo done
EOF

  if ${_PRINT_TRACE:-false} || ${_FAILURE_EXPECTED:-false}; then
    debug "Generating Password Store key:\n  $ gpg --batch --full-generate-key <<<\"" \
      "\n$(echo "${unattended_key_generation_parameters}" \
           | sed 's/^Passphrase: .\+/Passphrase: ---/' \
           | sed 's/^\([^:]\+\): $/\1: <*** ALERT: MISSING ***>/' \
           | sed 's/^/    /')\""
    ! ${_FAILURE_EXPECTED:-false} || echo
  fi

  gpg --batch --full-generate-key <<<"${unattended_key_generation_parameters}"

  # STDERR:
  # gpg: Generating a default key
  # gpg: revocation certificate stored as
  #   '/Users/user/.gnupg/openpgp-revocs.d/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.rev'
  # gpg: done
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

# Use --with-colons to parse GPG output.
#
# - E.g., consider:
#     $ gpg --list-keys Email@Address
#     pub   ed25519 2024-05-31 [SC]
#           EA9D8C075D4A2E2C68AD9D586360A06DB40CDD10
#     ...
#
#     $ gpg --list-secret-keys Email@Address | awk 'NR == 2 {print $NF}'
#     EA9D8C075D4A2E2C68AD9D586360A06DB40CDD10
#
# - Vs., e.g.:
#     $ gpg --list-keys --with-colons Email@Address
#     tru::1:1717137579:0:3:1:5
#     pub:u:255:22:6360A06DB40CDD10:1717134680:::u:::scESC:::::ed25519:::0:
#     ...
#
#     $ gpg --list-keys --with-colons Email@Address | awk -F: '/^pub:/ { print $5 }'
#     6360A06DB40CDD10
#
# - Or:
#     $ gpg --list-secret-keys --with-colons Email@Address
#     sec:u:255:22:6360A06DB40CDD10:1717134680:::u:::scESC:::+::ed25519:::0:
#     ...
#
#     $ gpg --list-secret-keys --with-colons Email@Address | awk -F: '/^sec:/ { print $5 }'
#     6360A06DB40CDD10

# REFER: https://github.com/gpg/gnupg/blob/master/doc/DETAILS
# - "Field 5 - KeyID"

print_password_store_key_ids () {
  local deprefixed
  deprefixed="$( \
    echo "${ONEOPEN_PASSWORD_STORE_EMAIL}" | sed 's/^\.\+//'
  )"

  if [ "${deprefixed}" != "${ONEOPEN_PASSWORD_STORE_EMAIL}" ]; then
    # SAVVY: `gpg --list-keys .foo.bar@baz` doesn't work, but removing dot does:
    #   $ gpg --list-keys .foo.bar@baz
    #   gpg: error reading key: No public key
    #   $ gpg --list-keys foo.bar@baz
    #   pub   ed25519 2024-06-01 [SC]
    #   ...
    >&2 info "ALERT: Using de-prefixed email to lookup GPG key"
  fi

  >&2 verbose "gpg --list-keys --with-colons \"${deprefixed}\""

  gpg --list-keys --with-colons "${deprefixed}" 2> /dev/null \
    | awk -F: '/^pub:/ { print $5 }'
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

infuse_symlinks_paddock_pwd () {
  infuse_symlinks_paddock_home_subdir ".password-store" "PWD"
}

# ***

remove_symlinks_paddock_pwd () {
  remove_symlinks_paddock_home_subdir ".password-store" "PWD"
}

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ #

_keypaddock_source_deps


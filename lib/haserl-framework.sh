#!/bin/sh
#
# This is a set of shell script functions that allow one to build
# MVC-style web frameworks based on cgi, shell scripts, and haserl templating.
#
# Dependencies:
#   haserl
#   gpg (ex: gnupg)
#   base64 (ex: coreutils-base64)
#
# base64 and gpg are only necessary if using cookies.


# Exports all variable definitions during initial setup.
set -a


##### Environment Variables #####

# Sets name of fifo files.
FIFO_INPUT="${FIFO_INPUT:=/tmp/haserl_framework_input}"
FIFO_OUTPUT="${FIFO_OUTPUT:=/tmp/haserl_framework_output}"

# Cleans up fifo files when app is terminated.
trap "rm -f $FIFO_INPUT; rm -f $FIFO_OUTPUT; exit" 1 2 3 6

# Uses SECRET or sets it to random string.
SECRET="${SECRET:=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128)}"


##### User Functions #####

before() {
  local code="$(cat -)"
  # Note that command-substitution $() strips ending newlines,
  # thus the EEOOLL and the subsequent brace-expansion to remove EEOOLL,
	# yet keep the new lines.
  run_before=$(printf '%s%s\n\nEEOOLL' "$run_before" "$code")
  run_before="${run_before%EEOOLL}"
  #printf 'BEFORE() called:%s' "$run_before" >&2
}

after() {
  local code="$(cat -)"
  run_after=$(printf '%s%s\n\nEEOOLL' "$run_after" "$code")
  run_after="${run_after%EEOOLL}"
}

route() {
  local match="$1"
  local method="$2"
  local code="$(cat -)"
  #set -a
  
  eval "action_match_$action_index='$match'"
  eval "action_method_$action_index='$method'"
  #eval "action_code_$action_index='$code'"
  # This has to have the extra $(printf ...) to capture potentially messy text.
  eval "action_code_$action_index=$(printf '$code')"
  
  action_index=$(( $action_index + 1 ))
  #set +a
}

# Sets a new line in headers.
header() {
  export headers=$(printf '%s\r\nEEOOLL' "$headers$1")
  headers="${headers%EEOOLL}"
}

content_type() {
  export content_type="$1"
}

# Redirects request.
# Params
#   $1  - location
#   $2  - status (must include code and message: "307 Temporary")
# See https://openwrt-devel.openwrt.narkive.com/K75cDiIZ/uhttpd-cgi-redirect
redirect() {
  location="$1"
  status="${2:-307 Temporary}"
  printf '%s\r\n' "Status: $status"
  printf '%s\r\n' "Location: $location"
  printf '%s\r\n'
	export redirected="$location"
}

# This is main render, called from the app or controller.
# Usage: render <view> <layout>
#render info layout
render() {
  #echo "Calling render with env:" >&2
  #env  >&2
  #echo "Test-error from render() function, arg1=$1, arg2=$2" >&2
  
  # Fork stubshell for each render() function, so current template,
  # which must be global, doesn't get confused when calling sub-render functions.
  (
    if [ ! -z "$1" ]; then
      export template="${1}"
    fi
  
    local layout="${2}"

    if [ ! -z "$layout" ]; then
      #export top_level_template="$template"
      headers
      #echo "Calling haserl layout with '$APPDIR/views/$layout'" >&2
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$layout"
    else
      #echo "Calling haserl view with '$APPDIR/views/$template'" >&2
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$template"
    fi
  )
}

yield() {
  render "$template"
  #echo "Calling yield with top_level_template '$top_level_template'" >&2
  #render "$top_level_template"
}

# Return non-haserl text to client.
# Make sure to set content_type appropriately.
output() {
  local data="${1:-$(cat -)}"
  headers
  printf '%s\r\n' "$data"
}

# See https://stackoverflow.com/questions/12873682/short-way-to-escape-html-in-bash
html_escape() {
  sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g'
}

# Sets a named cookie with data.
# Params  $1   name
#         $2   data
#         $3.. options, such as: Max-Age=3600 Another-Opt=whatever
# Cookie option semicolon separators are automatically added.
# For encrypted vs signed cookies, see the following.
# https://stackoverflow.com/questions/41467012/what-is-the-difference-between-signed-and-encrypted-cookies-in-rails
# See https://unix.stackexchange.com/questions/65803/why-is-printf-better-than-echo.
set_cookie() {
  local name="$1"
  local data="$2"
  shift; shift;
  local enc_cookie_data=$(printf '%s' "$data" | encrypt)
  local cookie_params=$(for x in $@; do printf '; %s' "$x"; done)
  local cookie="Set-Cookie: $name=$enc_cookie_data$cookie_params"
  #printf 'COOKIE:\n%s\nEND_COOKIE\n\n' "$cookie" >&2
  header "$cookie"
}

get_cookie() {
  local name="$1"
  eval "local raw=\$COOKIE_$name"
  if [ -z "$raw" ]; then return 1; fi
  printf '%s' "$raw" | decrypt
}

# Uses GnuPG (gpg) for cookie encryption.
# See https://gist.github.com/pmarreck/5388643
#
# Encryption functions. Requires the GNUpg "gpg" commandline tool. On OS X, "brew install gnupg"
# Explanation of options here:
# --symmetric - Don't public-key encrypt, just symmetrically encrypt in-place with a passphrase.
# -z 9 - Compression level
# --require-secmem - Require use of secured memory for operations. Bails otherwise.
# cipher-algo, s2k-cipher-algo - The algorithm used for the secret key
# digest-algo - The algorithm used to mangle the secret key
# s2k-mode 3 - Enables multiple rounds of mangling to thwart brute-force attacks
# s2k-count 65000000 - Mangles the passphrase this number of times. Takes over a second on modern hardware.
# compress-algo BZIP2- Uses a high quality compression algorithm before encryption. BZIP2 is good but not compatible with PGP proper, FYI.
#
# Expects stdin with data, $1 with optional passphrase.
encrypt() {
  # #rslt=$(gpg --symmetric --passphrase "$passph" -q -z 9 --require-secmem --cipher-algo AES256 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-mode 3 --s2k-count 99 --compress-algo BZIP2 $@ | base64 - 2>&1)
  # local rslt=$(gpg --symmetric --passphrase "$passph" -q -z 9 --require-secmem --cipher-algo AES256 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-mode 3 --s2k-count 99 $@ | base64 -w 0 - )
  # 
  # # This will get a digest. See gpg man page.
  # # echo 'bill' | gpg -q -z 9 --require-secmem --print-md SHA1 | base64 -
  # 
  # #echo "ENCRYPT result: $rslt" >&2
  # printf "$rslt"
  
  gpg --passphrase "${1:-$SECRET}" \
    --symmetric \
    -q -z 9 \
    --require-secmem \
    --cipher-algo AES256 \
    --s2k-cipher-algo AES256 \
    --s2k-digest-algo SHA512 \
    --s2k-mode 3 \
    --s2k-count 99 |
  base64 -w 0 - |
  cookie_safe 
}

# Expects stdin with data, $1 with optional passphrase.
decrypt() {
  # local raw="$(cat - 2>&1)"
  # local pass="${1:-$secret}"
  # echo "DECRYPT raw stdin: $raw" >&2
  # if [ -z "$raw" ]; then return 1; fi
  # local base64_decoded="$(printf $raw | base64 -d - 2>&1)"
  # echo "DECRYPT base64_decoded: $base64_decoded" >&2
  #   local rslt="$(printf $base64_decoded | gpg -q -d --passphrase $pass)"
  # #echo "DECRYPT result: $rslt" >&2
  # printf "$rslt"
  
  cat - | cookie_unsafe | base64 -d - | gpg -q -d --passphrase "${1:-$SECRET}"
}

# Makes base64 data safe for cookies.
# Expects stdin.
# See https://github.com/mochi/mochiweb/issues/37
cookie_safe() {
  sed 's/=/!/g; s/\+/\-/g; s/\//_/g'
}

# Expects stdin.
cookie_unsafe() {
  sed 's/\-/\+/g; s/_/\//g; s/!/=/g'
}

# # Expects stdin. 
# urlencode(){
#   local rslt=$(cat - | sed 's/ /%20/g;s/!/%21/g;s/"/%22/g;s/#/%23/g;s/\$/%24/g;s/\&/%26/g;s/'\''/%27/g;s/(/%28/g;s/)/%29/g;s/:/%3A/g')  # ;s/\=/%3A/g
#   echo "URLENCODE result: $rslt" >&2
#   printf "$rslt"
# }
# 
# # Expects stdin
# urldecode(){
#   local rslt=$(echo -e "$(sed 's/+/ /g;s/%\(..\)/\\x\1/g;')")
#   echo "URLDECODE result: $rslt" >&2
#   printf "$rslt"
# }


##### Internal Setup & Server Functions #####

setup() {
  if [ ! -z $is_setup ]; then
    return 0
  fi
    
  if [ -z "$APPDIR" ]; then
    APPDIR="$( dirname "$(readlink -f "$0")" )"
  fi

  action_index=1
  is_setup=true
}

# Loads the framework into a background server process.
# Waits for input - a string of ENV from the cgi via fifo input,
# then evals the input in a subshell,
# then calls run() and returns the result to the cgi via fifo output.
#
# NOTE: Here is a hacky netcat server loop that accepts headers & env,
#   and sends them to the fifo input. This could work if the proxy_pass could send env (but I don't think they can).
#   while true; do cat /tmp/haserl_framework_output | ncat -l 0.0.0.0 1500 | sed -E 's/^([a-zA-Z0-9\-]+)\: /\1\=/g' | tee /tmp/haserl_framework_input; done
#
server() {
  rm -f "$FIFO_INPUT" "$FIFO_OUTPUT"
  mkfifo "$FIFO_INPUT" "$FIFO_OUTPUT"
  chmod 600 "$FIFO_INPUT" "$FIFO_OUTPUT"
  
  echo "$(date -Iseconds) Running the Haserl Framework Server v0.0.1"
  #echo "FIFO_INPUT: $FIFO_INPUT"
  #echo "FIFO_OUTPUT: $FIFO_OUTPUT"
  echo "Use the following code in a cgi script file:
  #!/usr/bin/haserl
  <% export -p > '$FIFO_INPUT' && cat '$FIFO_OUTPUT' %>"
  
  while true; do
    # Gets input from fifo.
    #local input="$(get_safe_fifo_input)"
    #echo "ENV-INPUT:"
    #echo "$input"
		# The above bit may be obsolete, since we are now using 'export -p'.
    
    # Forks to a subshell to process the request, so env & global vars won't get clobbered.
    (
      set -a
      #eval "$input"  # see above.
			eval "$(cat $FIFO_INPUT)"
      unset TERMCAP
      set +a
      printf '%s\n' "$(date -Iseconds) $REQUEST_METHOD $REQUEST_URI"
			# The tee allows you to stuff all page responses into a file.
      #run | tee "$FIFO_OUTPUT" > /dev/null  #/tmp/haserl_page_output.html
			run > "$FIFO_OUTPUT"
    )
  done
}

# Runs the action after routes have been defined by user.
# NOTE:
#   All stdout during the request 'run' will be sent to the fifo-output, and therefore back to the cgi.
#   Use stderr during the request 'run' for all messages that should be sent back to server stdout or log.
#
# Expects no input from stdin or from args.
# Assumes all necessary data is in env vars.
#
run() {
  { 
		# Experimental rewrite PATH_INFO if '/'
		if [ "$REQUEST_URI" = "$SCRIPT_NAME/" ]; then
			export PATH_INFO='/'
		fi
    # This is needed for when path-info is empty or '/'.
		# PATH_INFO will be null even if request is '/' (at least in openwrt).
		# The above PATH_INFO modification may make this following bit obsolete.
    local path_info="$PATH_INFO"
    if [ -z "$path_info" ]; then
      path_info='/'
    fi
    
    # Selects matching PATH_INFO and REQUEST_METHOD (if request-method constraint is defined),
    # then calls action associated with route.
    for i in $( seq 1 $(($action_index - 1)) ); do
      eval "local match=\$action_match_$i"
      eval "local code=\$action_code_$i"
      eval "local method=\$action_method_$i"
      #export RUN_LOOP_$i="i:$i, action_match_$i:$match, PATH_INFO:$PATH_INFO, action_code_$i: $code"
      if [ "$match" == "$path_info" ] && [ "$method" == "$REQUEST_METHOD" -o -z "$method" ]; then
        run_before
        #echo "Test-error from just before (eval 'code') within run() function." >&2
				if [ -z "$redirected" ]; then
	        eval "$code" #2>>haserl_framework.log
	        printf '\r\n'
				fi
        run_after >&2
        return 0
      fi
    done

    # If no path-info matches a defined route, output a generic response,
    # and then return 1.
    content_type 'text/plain'
    #headers
    #echo "Error: action failed"
    #echo "$!"
    output "haserl_framework: an error occurred, or no action matched PATH_INFO '$PATH_INFO'\
    $1"
    return 1
  } #2>>haserl_framework.log
}

run_before() {
  if [ ! -z "$run_before" ]; then
    #printf 'RUN_BEFORE:\n%s\nEND_RUN_BEFORE\n' "$run_before" >&2
    eval "$run_before"
  fi
}

run_after() {
  if [ ! -z "$run_after" ]; then
    #printf 'RUN_AFTER:\n%s\nEND_RUN_AFTER\n' "$run_after" >&2
    eval "$run_after"
  fi
}

# Formats & returns headers for output.
headers() {
  # According to RFC 2616, proper header-block termination should be \r\n\r\n (I think).
  # printf 'HEADERS:\n%s\nEND_HEADERS\n\n' "$headers" >&2
  export headers=$(printf '%s\r\n%sEEOOLL' "Content-Type: ${content_type:-text/html}" "$headers")
  headers="${headers%EEOOLL}"
  #printf 'HEADERS:\n%s\nEND_HEADERS\n\n' "$headers" >&2
  printf '%s\r\n' "$headers"
}

# Filters fifo-input env string, so it can be eval'd safely.
#   Escapes single-quotes first.
#   Adds a quote after '=' to any line that doesn't begin with a space or tab.
#   Adds a quote at end of any line that doesn't end with '\'.
get_safe_fifo_input() {
  cat $FIFO_INPUT | sed "s/'/'\\\''/g; /^[^ \t]/{s/=/='/}; /[^\\]$/{s/$/'/}"
}


##### Load-time Functions #####

# Runs the setup function when after all other functions have loaded.
setup

# We need the framwork path so a helper can load the framework in views (which are a separate process).
# TODO: Should this be in the setup() function?
if [ -z "$framework" ]; then
  # This only gets the app path.
  #framework="$(readlink -f "$0")"
  # This gets the 2nd arg that was passed to the 'source' command in the app.
  # It's hacky, but it works just fine.
  framework="$1"
fi

set +a

# Loads user-defined helpers (without exporting x).
for x in "$APPDIR"/helpers/*.sh; do
  source "$x"
done


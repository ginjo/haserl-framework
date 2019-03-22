#!/bin/sh
#
# This is a set of shell script functions that allow one to build
# MVC-style web frameworks based on cgi, shell scripts, and haserl templating.
#
# Dependencies:
#   haserl
#   gpg (ex: gnupg)
#   base64 (ex: coreutils-base64)
#   socat
#
# Base64 and gpg are only necessary if using cookies.
# Socat is only required if using scgi or if serving this app
# from a machine other than the web server's.
#
# NOTE: Care is taken to prevent command injection.
# See https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)
# Test for vulnerabilities at all points of 'eval', especially where user-input is handled.
# Test potential points of injection with these characters:
#   bad='{ }  ( ) < > & * ? | = ? ; [ ]  $ ? # ~ ! . ? %  / \ : + , `'\''"'
# This should not fail: eval "x=\""'$bad'\"; echo "$x"
# This should not fail: http://host/cgi-bin/proxy.cgi/env?dir=%3Bcat%20/etc/passwd
# This should not fail: http://host/cgi-bin/proxy.cgi/env?;%3Bcat%20/etc/passwd;=something


# Uses SECRET or sets it to random string.
export SECRET="${SECRET:=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128)}"
export HF_DIRNAME="${HF_DIRNAME:=$(dirname $0)}"
export HF_FRAMEWORK="${HF_FRAMEWORK:=$HF_DIRNAME/framework.sh}"
export ROGUE_OUTPUT='104'

. "$HF_DIRNAME/logging.sh"

# Exports all variable definitions during initial setup.
set -a

##### User Functions #####

before() {
  log 5 "Defining 'before' function"
  local code="$(cat -)"
  # Note that command-substitution $() strips ending newlines,
  # thus the EEOOLL and the subsequent brace-expansion to remove EEOOLL,
  # yet keep the new lines.
  run_before=$(printf '%s%s\n\nEEOOLL' "$run_before" "$code")
  run_before="${run_before%EEOOLL}"
  #printf 'BEFORE() called:%s' "$run_before" >&2
}

after() {
  log 5 "Defining 'after' function"
  local code="$(cat -)"
  run_after=$(printf '%s%s\n\nEEOOLL' "$run_after" "$code")
  run_after="${run_after%EEOOLL}"
}

route() {
  local match="$1"
  local method="$2"
  local code="$(cat -)"
  log 5 '-echo "Defining route $match $method"'
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
  log 6 "Setting header $1"
  export headers=$(printf '%s\r\nEEOOLL' "$headers$1")
  headers="${headers%EEOOLL}"
}

content_type() {
  export content_type="$1"
  log 6 '-echo "Set content type to $content_type"'
}

# Redirects request.
# Params
#   $1  - location
#   $2  - status (must include code and message: "307 Temporary")
# See https://openwrt-devel.openwrt.narkive.com/K75cDiIZ/uhttpd-cgi-redirect
redirect() {
  location="$1"
  status="${2:-307 Temporary}"
  log 4 '-echo "Redirecting  to $location, with status $status"'
  #   printf '%s\r\n' "Status: $status"
  #   printf '%s\r\n' "Location: $location"
  #   printf '%s\r\n' "Connection: Close"
  #   printf '%s\r\n'
  header "Status: $status"
  header "Location: $location"
  header "Connection: Close"
  export redirected="$location"
  headers
} >&100

# This is main render, called from the app or controller.
# Usage: render <view> <layout>
#render info layout
render() {
  # Fork stubshell for each render() function, so current template,
  # which must be global, doesn't get confused when calling sub-render functions.
  # TODO: Is this subshelling still necessary with new architecture.
  (
    if [ ! -z "$1" ]; then
      export template="${1}"
    fi
  
    local layout="${2}"

    log 5 '-echo "Rendering with $template $layout"'

    if [ ! -z "$layout" ]; then
      #export top_level_template="$template"
      headers
      log 5 '-echo "Calling haserl layout with $APPDIR/views/$layout"'
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$layout"
    else
      log 5 '-echo "Calling haserl view with $APPDIR/views/$template"'
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$template"
    fi
  )
} >&100

yield() {
  log 5 '-echo "Yielding with $template"'
  render "$template"
  #echo "Calling yield with top_level_template '$top_level_template'" >&2
  #render "$top_level_template"
} >&100

# Return non-haserl text to client.
# Make sure to set content_type appropriately.
output() {
  log 5 'Running output()'
  local data="${1:-$(cat -)}"
  headers
  printf '%s\r\n' "$data"
} >&100

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
  log 6 '-echo "Called set_cookie with $name $data"'
  shift; shift;
  local enc_cookie_data=$(printf '%s' "$data" | encrypt)
  local cookie_params=$(for x in $@; do printf '; %s' "$x"; done)
  local cookie="Set-Cookie: $name=$enc_cookie_data$cookie_params"
  #printf 'COOKIE:\n%s\nEND_COOKIE\n\n' "$cookie" >&2
  header "$cookie"
}

get_cookie() {
  local name="$1"
  log 6 '-echo "Called get_cookie with $name"'
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
  log 5 "Running setup()"
  if [ ! -z $is_setup ]; then
    return 0
  fi
  
  # TODO: Should this be in server.sh, or stay here? Where is it used?
  APPDIR="${APPDIR:=$( dirname "$(readlink -f "$0")" )}"

  # Same here as above.
  PUBLICDIR="${HF_PUBLIC:=${APPDIR}/public}"

  action_index=1
  is_setup=true
}

# Runs the action after routes have been defined by user.
# Expects request env vars to be populated already.
#
#	For safety, normal stdout of the run() funtion is redirected to $ROGUE_OUTPUT fd (defaults to '104').
# All client-bound output during the request 'run' should be sent to &100.
# Use stderr during the request 'run' for all messages that should be sent back to server stdout or log.
#
# Expects no input from stdin or from args.
# Assumes all necessary data is in env vars.
#
run() {
  log 5 "Called run()"
  # Experimental set PATH_INFO to '/' under certain circumstances.
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
  
  # Serves static assets.
  # NOTE: Experimental, this does not server the assets properly yet.
  if [ -f "${PUBLICDIR}${path_info}" ]; then
    log 4 '-echo "Serving static asset ${PUBLICDIR}${path_info}"'
    header "Content-Type: application/octet-stream"
    headers >&100
    cat "${PUBLICDIR}${path_info}" >&100
    return 0
  fi
   
   # Selects matching PATH_INFO and REQUEST_METHOD (if request-method constraint is defined),
   # then calls action associated with route.
  # Any stdout here goes back to browser, but this loop doesn't generate any content iteself.
   for i in $( seq 1 $(($action_index - 1)) ); do
     eval "local match=\$action_match_$i"
     eval "local code=\$action_code_$i"
     eval "local method=\$action_method_$i"
     #if [ "$match" == "$path_info" ] && [ "$method" == "$REQUEST_METHOD" -o -z "$method" ]; then
    if [ "$method" == "$REQUEST_METHOD" -o -z "$method" ] && match_url "$path_info" "$match"; then
       run_before >&2
       #echo "Test-error from just before (eval 'code') within run() function." >&2
      if [ -z "$redirected" -a $? = 0 ]; then
        log 6 "Running action with match ($match) method ($method) code ($code)"
        eval "$code"
        printf '\r\n' >&100
      fi
      #echo "Some rogue text in the run() function"
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
   output "haserl_framework: an error occurred, or no action matched $REQUEST_METHOD '$PATH_INFO'\
   $1"
   return 1
} 100>&1 1>&$ROGUE_OUTPUT

run_before() {
  if [ ! -z "$run_before" ]; then
    log 5 "Running 'before' actions"
    log 6 "Before actions to run: $run_before"
    #printf 'RUN_BEFORE:\n%s\nEND_RUN_BEFORE\n' "$run_before" >&2
    eval "$run_before"
  fi
}

run_after() {
  if [ ! -z "$run_after" ]; then
    log 5 "Running 'after' actions"
    log 6 "After actions to run: $run_after"
    #printf 'RUN_AFTER:\n%s\nEND_RUN_AFTER\n' "$run_after" >&2
    eval "$run_after"
  fi
}

# Formats & returns headers for output.
# TODO: Create a clear framework-wide policy for handling headers. This is currently kinda messy.
headers() {
  # According to RFC 2616, proper header-block termination should be \r\n\r\n,
  # and each header line should be terminated with \r\n.
  # printf 'HEADERS:\n%s\nEND_HEADERS\n\n' "$headers" >&2
  header "Connection: close"
  export headers=$(printf '%s\r\n%sEEOOLL' "Content-Type: ${content_type:-text/html}" "$headers")
  if echo "$GATEWAY_INTERFACE" | grep -qv '^CGI' && [ ! "$SCGI" == '1' ]; then
    headers=$( printf '%s\r\n%s' "HTTP/1.1 ${status:-200 OK}" "$headers")
  fi
  headers="${headers%EEOOLL}"
  #printf 'HEADERS:\n%s\nEND_HEADERS\n\n' "$headers" >&2
  printf '%s\r\n' "$headers"
}

# Filters fifo-input env string, so it can be eval'd safely.
# Is intended to take output from 'env' and make it more like 'export -p'.
#   Escapes single-quotes first.
#   Adds a quote after '=' to any line that doesn't begin with a space or tab.
#   Adds a quote at end of any line that doesn't end with '\'.
# This will not be needed if 'export -p' turns out to be reliable.
get_safe_fifo_input() {
  cat $FIFO_INPUT | sed "s/'/'\\\''/g; /^[^ \t]/{s/=/='/}; /[^\\]$/{s/$/'/}"
}

# Matches PATH_INFO string with route definition,
# creating variables from uri-inline-params if they exist.
match_url() {  # <url> <matcher>
  #echo "URL: $1, MATCHER: $2" >&2
  
  # Replaces var labels in url with general regexes.
  # This is used to see if the URL matches the route in general.
  gate_builder='s|:[[:alnum:]_]\{1,99\}|[^/]*|g'
  #echo "GATE_BUILDER: $gate_builder" >&2
  
  # Builds pattern to match this label instance against URL.
  local gate="$(echo $2 | sed -e $gate_builder )"
  #echo "URL GATE: $gate" >&2
  
  # Matches URL against given route... or not.
  if ! echo "$1" | grep -q "^$gate$"; then
    return 1
  # else
  #   echo "URL '$1' matched route '$2' with pattern '^$gate\$'" >&2
  fi

  # Picks out labels from url.
  labels="$(echo $2 | grep -o ':\w*')"
  #echo "$labels" >&2
  
  for x in $labels; do
    # Builds pattern_builder to extract pattern-matcher for this label instance.
    local pattern_builder="s|$x|\\\([^/]*\\\)|;s|:[[:alnum:]_]\{1,99\}|[^/]*|g"
    #echo "PATTERN_BUILDER: $pattern_builder" >&2
    
    # Builds sed pattern to match this label instance against URL.
    local pattern="s|$(echo $2 | sed -e $pattern_builder )|\\1|g"
    #echo "PATTERN: $pattern" >&2
    
    # Extracts this label's param from URL.
    result="$(echo $1 | sed -e $pattern)"
    #echo "RESULT: $result" >&2
    
    # Assigns param value to var.
    x="$(echo $x | tr -d ':')"
    #echo "EVAL: PARAM_${x}=${result}" >&2
    # NOTE: Very important to eval the $result var literally and
    # not the expanded $result, or you will eval user input!
    # That is why the single-quotes.
    # Use this URL to test against malicious input: http://wndr3800/cgi-bin/proxy.cgi/order/"';$(ls);'bill/9|99;
    #eval "PARAM_${x}="'${result}'
    eval "PARAM_${x}=\""'${result}'\"
  done
}


##### Load-time Functions #####

# Runs the setup function after all other functions have loaded.
setup

# # We need the framwork path so a helper can load the framework in views (which are a separate process).
# # TODO: Should this be in the setup() function?
# if [ -z "$framework" ]; then
#   # This only gets the app path.
#   #framework="$(readlink -f "$0")"
#   # This gets the 2nd arg that was passed to the 'source' command in the app.
#   # It's hacky, but it works just fine.
#   framework="${1:-$HF_DIRNAME/framework.sh}"
# fi

set +a

# Loads user-defined helpers (without exporting x).
for x in "$APPDIR"/helpers/*.sh; do
  source "$x"
done


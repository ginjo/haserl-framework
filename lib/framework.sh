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
  # TODO: You can get rid of the EEOOLL, because leading new-lines are
  # also cut when using $(). See header/headers for how to handle new-lines.
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
# The EEOOLL is needed to preserve the final \r\n,
# since command substitution $() strips it.
header() {
  log 6 "Setting header $1"
  #export headers=$(printf '%s\n%s' "$headers" "$1")
  NL=$'\n'
  # Concatenates existing headers with new header,
  # with a newline in between if headers existed.
  export headers="${headers}${headers:+${NL}}$1"
}

content_type() {
  export content_type="$1"
  log 6 '-echo "Set content type to $content_type"'
}

content_length() {
	export content_length="$1"
	log 6 '-echo "Set content length to $content_length"'
}

# Redirects request.
# Params
#   $1  - location
#   $2  - STATUS (must include code and message: "307 Temporary")
# See https://openwrt-devel.openwrt.narkive.com/K75cDiIZ/uhttpd-cgi-redirect
redirect() {
  location="$1"
  STATUS="${2:-307 Temporary}"
  log 5 '-echo "Redirecting to $location $STATUS"'
  #   printf '%s\r\n' "Status: $STATUS"
  #   printf '%s\r\n' "Location: $location"
  #   printf '%s\r\n' "Connection: Close"
  #   printf '%s\r\n'
  #header "Status: $STATUS"
  header "Location: $location"
  export redirected="$location"
  # Moving headers to somewhere downstream.
  #headers
} >&100

# This is main render, called from the app or controller.
# Usage: render <view> <layout>
#render info layout
render() {
  # Fork subshell for each render() function, so current template,
  # which must be global, doesn't get confused when calling sub-render functions.
  # TODO: Is this subshelling still necessary with new architecture.
  #(
    if [ ! -z "$1" ]; then
      export template="${1}"
    fi
  
    local layout="${2}"

    log 5 '-echo "Rendering with $template $layout"'

    if [ ! -z "$layout" ]; then
      # Moving headers to somewhere downstream.
      #headers   #| tee -a /root/haserl_framework_app/debug_headers.log
      log 5 '-echo "Calling haserl layout with $APPDIR/views/$layout"'
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$layout"
    else
      log 5 '-echo "Calling haserl view with $APPDIR/views/$template"'
      echo "${REQUEST_BODY:-$POST_body}" | haserl "$APPDIR/views/$template"
    fi
  #)
} >&100

yield() {
  log 5 '-echo "Yielding with $template"'
  render "$template"
} >&100

# Return non-haserl text to client.
# Make sure to set content_type appropriately.
output() {
  log 5 'Running output()'
  local data="${1:-$(cat -)}"
  # Moving headers to somewhere downstream.
  #headers
  printf '%s' "$data"
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
	# In ash (and bourne) shell, position param ranges ${*:2} do not work.
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

# Runs the action after routes have been defined by user.
# Expects request env vars to be populated already.
#
# For safety, normal stdout of the run() function is redirected to $ROGUE_OUTPUT fd (defaults to '104').
# All client-bound output during the run() func should be sent to >&100.
# Use stderr during the request 'run' for all messages that should be sent back to server stdout or log.
# User-space functions like render(), output(), redirect(), etc all send output to >&100 by default.
#
# Expects no input from stdin or from args.
# Assumes all necessary data is in env vars.
#
run() {
  log 5 "Beginning run()"
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

  export STATUS="${STATUS:-200 OK}"

	# {
		if [ -f "${PUBLICDIR}${path_info}" ]; then
			log 5 '-echo "Sending static asset ${PUBLICDIR}${path_info}"'
			send_static_asset "${PUBLICDIR}${path_info}"
		elif local matched_action=$(select_matching_action "$path_info"); then
			log 5 '-echo "Calling call_action with $matched_action"'
			call_action "$matched_action"
		else
			log 5 'Sending 404'
			send_404
		fi
	# } #100>&1 1>&$ROGUE_OUTPUT
  
	log 6 "End run()"
} 100>&1 1>&$ROGUE_OUTPUT

# Expects path-info on $1.
select_matching_action() {
	local path_info="${path_info:-$1}"
	for i in $( seq 1 $(($action_index - 1)) ); do
    eval "local match=\$action_match_$i"
    eval "local code=\$action_code_$i"
    eval "local method=\$action_method_$i"
		if [ "$method" == "$REQUEST_METHOD" -o -z "$method" ] && match_url "$path_info" "$match"; then
			printf '%s ' "$match" "$method" "$path_info"
			printf '\n%s\n' "$code"
			break
		fi
	done
}

# Expects input (match, method, pathinfo, code) on $1.
call_action() {
	local action_info=$(printf '%s' "$1" | head -n 1)
	local action_code=$(printf '%s' "$1" | tail -n +2)
	run_before >&2
  if [ -z "$redirected" -a $? = 0 ]; then
    log 6 '-echo "Calling eval with action_code (match, method, path_info : $action_info)"'
    eval "$action_code"
  fi
  #echo "Some rogue text in the run() function"
  if [ -z "$redirected" ]; then
    run_after >&2
  fi
}

# Expects full-path on $1.
send_static_asset() {
	local full_path="${full_path:-$1}"
	log 4 '-echo "Serving static asset $full_path"'
  content_type 'application/octet-stream'
  # Moving headers to somewhere downstream.
  #headers >&100
  cat "${full_path}" >&100
}

send_404() {
	# If no path-info matches a defined route, output a generic response,
  # and then return 1.
  content_type 'text/plain'
  #headers
  #echo "Error: action failed"
  #echo "$!"
  STATUS='404 Not Found'
  output "haserl_framework: an error occurred, or no action matched $REQUEST_METHOD '$PATH_INFO'."
}

# Formats & returns headers for output.
# TODO: Create a clear framework-wide policy for handling headers. This is currently kinda messy.
#       Dont modify headers or data, when headers() is called. Must be callable multiple times,
#       for checking logging or user query.
headers() {
  # According to RFC 2616, proper header-block termination should be \r\n\r\n,
  # and each header line should be terminated with \r\n.
  # TODO: Final output status should maybe be handled by run() or process_request().
  STATUS="${STATUS:-200 OK}"
  if echo "$GATEWAY_INTERFACE" | grep -qv '^CGI' && [ ! "$SCGI" == '1' ]; then
    local status_header="HTTP/1.0 $STATUS"
  else
    local status_header="Status: $STATUS"
  fi
  # Content-Length
  local content_length_header="Content-Length: ${content_length:-$1}"
  # Should be valid HTTP-date format.
  local date_header="Date: $(date -u +%a,\ %d\ %b\ %Y\ %H:%M:%S\ GMT)"
  local keep_alive_header="${KEEP_ALIVE:-Connection: close}"
  local content_type_header="Content-Type: ${content_type:-text/html}"

  export OUTPUT_HEADERS=$(
    printf '%s\n' "$status_header" "$date_header" "$content_type_header" "$content_length_header" "$keep_alive_header" "$headers"
    #printf '%s' "$headers"
  )
  
  log 6 "OUTPUT_HEADERS:"
  log 6 "${OUTPUT_HEADERS}"
  
  printf '%s\n\n' "${OUTPUT_HEADERS}" | sed 's/$/\r/'

  #headers="${headers%EEOOLL}"
  #printf 'HEADERS:\n%s\nEND_HEADERS\n\n' "$headers" >&2
  #printf '%s\r\n' "$headers"
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


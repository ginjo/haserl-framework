#!/bin/sh

##### A shell-based application server #####
#
# TODO: Convert server & app daemon to this example of handling
# the request almost entirely in the app-daemon process.
# Consider putting the socat 'system' code in a env var and evaling it.
#
# Application daemon:
#   while :; do
#     IFS= read -r line < fifo; {
#	      echo "Hi, you sent '$line'"
#	      echo "Sender's FDs:"
#	      ls -la "/proc/${line:0:5}/fd"
#	    } | tee fifo2
#	    echo ''
#	  done
#
# TCP daemon:
#   socat -t1 -T5 tcp-l:1500,reuseaddr,fork system:'echo "$$ $(cat -)" | tee fifo >&2; cat fifo2'
#
# Test:
#   echo 'Hey' | nc wndr3800 1500
#

# Another Simple Example
#
# socat -t1 tcp-l:1500,reuseaddr,fork system:'cat <fifo2 & cat - >fifo'
#
# while :; do echo "loop"; cat fifo | (for x in 1 2 3; do IFS= read -r resp; echo "Reply: $resp"; done | tee fifo2); done
#
# printf '%s\r\n%s\r\n%s\r\n' 'hey' 'there' 'bill' | nc wndr3800 1500
#
# NOTE: In ash & bash, the last section of a pipeline is run in a subshell,
# so variable changes and/or function declarations will not persist beyond the pipeline.
#
# For some shell pipeline alligators, see https://backreference.org/2010/10/23/on-pipes-subshells-and-descriptors/
#


export FIFO_INPUT="${FIFO_INPUT:-/tmp/fifo_input}"
export FIFO_OUTPUT="${FIFO_OUTPUT:-/tmp/fifo_output}"
export FIFO_TOKEN="${FIFO_TOKEN:-/tmp/fifo_token}"
export HASERL_ENV="${HASERL_ENV:-/tmp/haserl_env}"
export PID_FILE="${PID_FILE:-/tmp/hf_server.pid}"
export HF_DIRNAME="${HF_DIRNAME:-$(dirname $0)}"
export HF_SERVER="${HF_SERVER:-$HF_DIRNAME/server.sh}"
#export SOCAT_ADDR="${SOCAT_ADDR:-tcp-l:1500,reuseaddr,shut-null,null-eof}"
export SOCAT_ADDR="${SOCAT_ADDR:-tcp-l:1500,reuseaddr}"
export PREFIX_HTTP_STANDARD_HEADERS
export HTTP_STANDARD_HEADERS="${HTTP_STANDARD_HEADERS:-$( tr '\n' ' ' <$HF_DIRNAME/http_headers.txt | awk '{gsub(/-/,"'_'"); print toupper($0)}' )}"
# Still need to export SOCAT_OPTS, even if default is null.
# If using the CGI interface, you will need to set -t to something above default (0.5), try 1 or 2.
export SOCAT_OPTS="${SOCAT_OPTS:--T60}"  

# Loads logging.
. "$HF_DIRNAME/logging.sh"

# The socat process takes input over tcp (or sockets),
# and sends it to the daemon via two fifo pipes.
# To keep the socat 'system' call simple, a handler function is called.
#
# Note that when socat 'system' call is reading an http request from stdin,
# you need to look at content type and specify exactly how many bytes to read.
# Otherwise, the read/head/cat/whatever command will hang on stdin, waiting
# for the client to send more data.
#
# Note that the hang-on-stdin is less likely to happen when data is received from a
# low-level tcp client like nc, ncat, or socat (because they are not http clients).
#
# Note that if -t is too small, the pipe will break before 'system' call is finished.
# Since we don't use the 'system' style any more, this might be irrelevant.
#
# NOTE: that -t should be large (-t10) if using cgi interface with nc, or responses will be cut short.
# This does not appear to be an issue if using cgi with direct piping to fifo files.
#
# NOTE: that -t should be small (-t0.2) if using scgi interface, or redirects will take forever.
#
# Socat default for -t (wait for other channel) is 0.5s. For -T (innactivity timeout) is never.
# See env vars above for HF defaults.
#
socat_server(){
	{
		#echo "Starting socat_server with handler (${1:-<undefined>})" >&2
		log 4 '-echo "Starting socat tcp/socket listener ($(get_pids))"'
		#socat -t5 tcp-l:1500,reuseaddr,fork system:". socat_server.sh && handle_http",nonblock=1    #,end-close
		# TODO: Allow server startup command to pass socat options and 1st addr to this command.
		#socat -d -t1 -T5 tcp-l:1500,reuseaddr,fork system:". ${HF_DIRNAME}/server.sh && handle_${1:-cgi}",nofork
		#socat -d -t0.2 -T5 tcp-l:1500,reuseaddr,fork exec:"${HF_SERVER} handle ${1:-scgi}"
		#socat -d -t1 -T5 $SOCAT_ADDR exec:"${HF_SERVER} handle"
		#socat -d -t1 -T10 $SOCAT_ADDR system:'cat - >"$FIFO_INPUT" | cat "$FIFO_OUTPUT"'
		#socat -d -t10 tcp-l:1500,reuseaddr,fork STDIO <"$FIFO_INPUT" | handle_request >"$FIFO_INPUT"
		
		# Forking socat with dual fifo files to/from request_loop. This works well.
		# The shut-null on addr1, combined with subshelling the handle_request call, is necessary
		# for redirects to work properly with this style of socat (forking with STDIO).
		# The shut-null on addr2 is experimental. The null-eof's are both experimental.
		# The keepalive doesn't seem to help redirects use keepalive.
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork,shut-null,null-eof,keepalive,setlk STDIO,shut-null,null-eof 1>"$FIFO_INPUT" 0<"$FIFO_OUTPUT"
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork STDIN!!STDOUT,setlkw 1>"$FIFO_INPUT" 0<"$FIFO_OUTPUT"
		
		# Sends uniq id to request loop, then trades data with dual uniq fifos, or with socat-created pipes.
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork system:'export id=$(exec sh -c '\''echo "$PPID"'\''); mkfifo "/tmp/hf_${id}_in" "/tmp/hf_${id}_out"; echo "${id}" > /root/haserl_framework_app/fifo; cat > "/tmp/hf_${id}_in" | { cat "/tmp/hf_${id}_out"; rm -f "/tmp/hf_${id}_*"; }',null-eof,pipes
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork system:'export id=$(exec sh -c '\''echo "$PPID"'\''); mkfifo "/tmp/hf_${id}_out"; echo "${id}" > /root/haserl_framework_app/fifo; cat "/tmp/hf_${id}_out"; rm -f "/tmp/hf_${id}_*"',pipes
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork system:'export id=$(exec sh -c '\''echo "$PPID"'\''); echo "${id}" > /root/haserl_framework_app/fifo; sleep 10',pipes
		#socat $SOCAT_OPTS $SOCAT_ADDR,fork system:'pid="$$"; printf %s "${pid}" >"$FIFO_TOKEN"; sleep 10',pipes
		# Sending newline here with printf, otherwise tokens will get stacked up in pipe with no line delimiter.
		# Using echo doesn't work, it somehow polutes the token with request data.
		socat $SOCAT_OPTS $SOCAT_ADDR,fork system:'pid="$$"; printf %s\\\n "${pid}" >"$FIFO_TOKEN"; sleep 10',pipes
		
		
		# # Loops with non-forking socat and uniq per-request single fifo file. This also works well.
		# # This does not require the request_loop function (since this IS the request loop here).
		# while [ $? == 0 ]; do
		# 	(
		# 	local loop_id=$(sspid)
		# 	local fifo="/tmp/hf_fifo_$loop_id"
		# 	rm -f "$fifo"
		# 	mkfifo "$fifo"
		# 	while [ ! -p "$fifo" ]; do echo "Waiting for fifo $fifo" >/tmp/log_103; done
		# 	log 5 "Beginning socat listener loop with ($loop_id)"
		# 	# The stdin-closing is experimental attempt to get the EOF back the client more reliably.
		# 	# At the time of this writing, it does not seem to make any difference here,
		# 	# however the app is working correctly here (and very quickly, using scgi).
		# 	# See the above URL re pipeline alligators.
		# 	socat $SOCAT_OPTS $SOCAT_ADDR,setlkw STDIO <"$fifo" | handle_socat_loop >"$fifo"
		# 	if [ $? != 0 ]; then
		# 		log 3 "Socat failed with exit code '$?'"
		# 	fi
		# 	# { socat -d -t10 tcp-l:1500,reuseaddr STDIO <"$fifo" && exec 1>&- ; } | handle_request >"$fifo"
		# 	rm -f "$fifo"
		# 	log 5 "Finished socat listener loop ($loop_id)"
		# 	)
		# done
				
	} >&103 2>&22  # Othwerwise, socat spits out too much data.
}

# Handles request-to-application IO by tapping into socat fifo IO directly.
handle_socat_loop() {
	local display_pids="$(get_pids)"
	log 4 '-echo "Listening for input from socat ($display_pids)"'
	while :; do
		log 6 '-echo "Handle_socat_loop (re)beginning possibly after forking subshell ($display_pids)"'
		IFS= read -r token <"$FIFO_TOKEN"
		
		# Go around again if bad/no data received from token pipe.
		if [ -z "$token" -o "${token/*[^0-9]*/bad}" == 'bad' ]; then
			log 3 "Handle_socat_loop received bad/empty token ($token) from $FIFO_TOKEN"
			continue
		# # Or if socat /proc/$token/fd/ not ready.
		# # I don't think this will work, since another read will clear a good token.
		# elif [ ! -d "/proc/$token/fd/" ]; then
		# 	log 4 "Socat pipes not ready in /proc/$token/fd/"
		# 	continue
		fi
		
		log 5 "Handle_socat_loop receiving request in (/proc/$token/fd/) ($display_pids)"
		# This is the main request subshell. Anything that happens in here should not
		# affect variables or environment of the main process.
		(
			# Get stdin/out from socat-created pipes.
			exec 0</proc/${token}/fd/0
			exec 1>/proc/${token}/fd/1
			handle_request #</proc/${token}/fd/0 >/proc/${token}/fd/1
			
			# Is this null byte necessary?
			#printf '\0'
			
			log 5 "Handle_socat_loop cleannig after handle_request for token ($token)"
			# Close stdin/out
			# TODO: Are these breaking CGI when socat -t is too small? (something is, but I can't find it).
			exec 0<&-
			exec 1>&-
			
			# This is needed to close out the socat 'system' subshell when using http or scgi interface,
			# since no sockets ever report EOF in this situation (and thus the need to keep the subshell open aritificially).
			log 5 '-echo "Killing socat system subshell (token $token)"'
			# This kill is necessary, if the response doesn't trigger the client to release the connection.
			# If you always have a content-length header, you shouldn't need this (I don't think).
			# Hmmm... still seems to be necessary for the scgi interface. Not sure why.
			if [ "$GATEWAY_INTERFACE" == 'SCGI' ]; then
				kill -1 "${token}" >&2
			fi
			
			# Pretty sure thas to be backgrounded here, but I don't remember why.
			# Might have something to do with the token-named fifo files & IO.
		) &
	done
}

# Handles request from socat server.
# Expects all data to be on stdin, except for optional first-line on $1.
# Stdout goes out stdout, back to request loop, then out to client.
handle_request() {
	local start_time="$(timer)"
	log 5 '-echo "Begin handle_request ($(get_pids))"'
	#log 6 '-ls -la /proc/$$/fd'
	local line="$1"
	local chr=''
	while :; do  #[ "$?" == "0" ]; do
		log 6 '-echo "Determining request type ($(get_pids))"'
		#chr=$(dd count=1 bs=1 2>&106)
		IFS= read -rn1 chr
		log 6 '-echo "Read ${#chr} chr from request:$chr"' #>&106
		line="$line$chr"
		[ -z "$line" ] && break 1
		
		log 6 "Inspecting beginning of request:$line"
		if printf '%s' "$line" | grep -qE '^[0-9]+:'; then
			log 5 '-echo "Calling handle_scgi with ($line)"'
			handle_scgi "$line"
			#break
		#elif printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE).*HTTP'; then
		elif printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE|HEAD) '; then
			log 5 '-echo "Calling handle_http with ($line)"'
			handle_http "$line"
			#break
		elif printf '%s' "$line" | grep -qE '^(export )?[[:alnum:]_]+='; then
			log 5 '-echo "Calling handle_cgi with ($line)"'
			handle_cgi "$line"
			#break
		#elif
			# TODO: Abort with 5XX error if end of first line.
		else
			log 6 '-echo "No handler found yet for request beginning with:$line"'
			continue
		fi
		
		# If you made it this far, you've completed a request.
		break
	done
	log 5 "End handle_request"
	
	local end_time="$(timer)"
	local elapsed_time=$(echo "$start_time $end_time" | awk '{print $2 - $1}')
	log 4 '-echo "Elapsed ${elapsed_time}s Start $start_time End $end_time"'
} # Stdout should go back to socat server. Do not redirect.

# This accepts and handles http input.
handle_http(){
	log 5 "Begin handle_http with '$1' ($(get_pids))"
	# All stdout in this block gets sent to process_request()

	export GATEWAY_INTERFACE='HTTP'
	
	IFS= read -r line
	local first_line="$1$line"
	log 6 "FIRST-LINE: $first_line"

	# This should probably be a custom env var like HTTP_REQUEST,
	# then parse that in its own function, or in the framework, or in process_request()
	export REQUEST_URI=$(echo "$first_line" | sed 's/^[[:alpha:]]\+ \([^ ]\+\) .*$/\1/')
	# TODO: Move this line further up the chain (closer to the framework).
	#export PATH_INFO="${PATH_INFO:-${REQUEST_URI#$}"
	export REQUEST_METHOD=$(echo "$first_line" | sed 's/^\([[:alpha:]]\+\) [^ ]\+ .*$/\1/')
	#log 5 "Reading raw http headers from stdin."

	# while [ ! -z "$line" -a "$line" != $'\r' -a "$line" != $'\n' -a "$line" != $'\r\n' ]; do
	# 	IFS= read -r line
	# 	input_headers="$input_headers""$line"$'\n'
	# done
	local input_headers=$(read_headers)
	
	local env_vars=$(http_headers_to_env_var "$input_headers")
	eval_input_env "$env_vars"
	
	# TODO: This extracts body from stdin and needs to be moved to process_request().
	#
	# if [ $(($len)) -gt 0 ]; then
	# 	log 6 '-echo "Calling head on stdin with -c $len"'
	# 	head -c $(($len))
	# fi
	#
	# or
	#
	# if [ $(($HTTP_CONTENT_LENGTH)) -gt 0 ]; then
	# 	log 6 '-echo "Calling head on stdin with -c $HTTP_CONTENT_LENGTH"'
	# 	head -c $(($HTTP_CONTENT_LENGTH))
	# fi
	
	log 5 'Calling process_request from handle_http()'
	#log 6 '-echo "Http input sent to process_request: $inpt"'
	process_request
	
	log 5 "End handle_http"
} # Stdout goes back to socat server. Do not redirect.

# Accepts and parses SCGI input on stdin, and sends it to process_request.
# Respons from process_request is returned on stdout to upstream handle_request.
# This function expects $1 containing the total num of characters in the scgi headers.
handle_scgi() {
	log 5 "Begin handle_scgi with '$1' ($(get_pids))"
	#log 6 '-ls -la /proc/$$/fd'
	
	export GATEWAY_INTERFACE='SCGI'
	
	# Arg $1 contains the total length of headers.
	# Gets all but the last character of $1 (last chr is a ':', which we don't want).
	local len="${1:0:$((${#1}-1))}"
	
	log 5 "Reading $len characters of scgi input"

	# Reads header length, reads headers, translates into env var code.
	# Must not use a variable to store scgi headers before translating null-byte,
	# since null-bytes can't be stored in variables.
	local scgi_headers=$(
		dd count=$(($len)) bs=1 2>&106 |
		tr '\0' '\n' |
		sed '$!N;'"s/\n/='/;s/$/'/"
		printf '\n'
	)
	log 6 '-echo "Parsed SCGI headers $scgi_headers"'
	
	# Drops the last 1 chrs from stdin (I think they were ',')
	IRS= read -rn1 dropped_chr
	log 6 '-echo "Dropped ($dropped_chr) from end of scgi input"'
	
	# # TODO: This functionality needs to be recreated in process_request().
	# #
	# # Gets remaining stdin containing request body, if exists.
	# # We use dd here cuz we might want to skip one or more bytes.
	# if [ $(($CONTENT_LENGTH)) -gt 0 ]; then
	# 	log 5 '-echo "Reading $CONTENT_LENGTH more chars as request body"'
	# 	export REQUEST_BODY=$(dd count=$(($CONTENT_LENGTH)) bs=1 skip=0 2>&106)
	# 	#echo "Request body: $REQUEST_BODY"
	# fi

	local env_vars=$(http_headers_to_env_var "$scgi_headers")
	eval_input_env "$env_vars"

	log 5 'Calling process_request from handle_scgi()'
	process_request
	
	log 5 "End handle_scgi"
} # Stdout goes back to socat server. Do not redirect.

# This accepts and handles cgi input containing env vars.
# Any pre-read data is available on $1.
handle_cgi(){
	log 5 "Begin handle_cgi with '$1' ($(get_pids))"
	# All stdout in this block gets sent to process_request()
	
	export GATEWAY_INTERFACE='CGI'
	
	# The use of socat here is necessary, because otherwise reading from stdin hangs.
	# This happens when pushing env vars from a cgi script to this app
	# using nc, socat, or directlly via fifo.
	# If receiving these cgi/haserl requests over the socat interface,
	# you may also need to adjust -t and -T on that interface using $SOCAT_OPTS.
	log 5 "Reading CGI input (env vars) from stdin."
	# TODO: Instead of socat here, create a generic function read_headers() to get all stdin up to a blank line.
	# That function will also be used for the handle_http() interface.
	#local cgi_headers="$1$(socat -u -T0.2 - -)"
	local cgi_headers="$1$(read_headers)"
	
	log 6 '-echo "Read CGI input (env vars) from stdin: $cgi_headers"'

	local env_vars=$(http_headers_to_env_var "$cgi_headers")
	eval_input_env "$env_vars"

	log 5 'Calling process_request from handle_cgi()'
	process_request
	
	# This doesn't help the lingering connection.
	#printf '\0'
	
	log 5 "End handle_cgi"
} # Stdout goes back to socat server. Do not redirect.

# Parses & evals the request env passed thru stdin (and existing env vars),
# and calls the framework action(s).
# Stdout will be sent back to request handler via stdout.
# Expects a LF delimited list of env variable definitions with single-quoted data, on stdin.
# Example: export MY_VAR='hey there'
process_request() {
	log 5 '-echo "Begin process_request ($(get_pids))"'
	#local input_env="$(cat -)"
	
	# This is handled in the request handlers now.
	#eval_input_env #"$input_env"

	# Disable unused, irrelevant, or troublesome env vars.
	unset TERMCAP
	
	# Omitting the colon in parameter expansion means test only for unset param.
	# Leaving the colon would test also for null param.
	# We don't want to modify a null PATH_INFO, so we omit the colon.
	export PATH_INFO="${PATH_INFO-${REQUEST_URI#$SCRIPT_NAME}}"
	
	if [ $(($CONTENT_LENGTH)) -gt 0 ]; then
		log 6 '-echo "Calling head on stdin with -c $CONTENT_LENGTH"'
		export REQUEST_BODY="$( head -c $(($CONTENT_LENGTH)) )"
	fi
	
	eval_haserl_env
	
	
	log 6 '-echo "Calling run() with env: $(env | sort)"'

	# # Should this go in the handle_http() funtion?
	# # Or in the framework run() function?
	# if echo "$GATEWAY_INTERFACE" | grep -qv '^CGI' && [ ! "$SCGI" == '1' ]; then
	# 	printf '%s\n' "HTTP/1.1 ${status:-200 OK}"
	# fi
	
	#headers
	#run
	{
		eval_to_var run_result run
		# I removed the final null-byte and added +1 here, but it doesn't always match the actual body content length.
		# The content-length header returned to client should always match the socat body length
		# reported in the socat log (using -v).
		#content_length "${#run_result}"
		content_length "$((${#run_result} + 1))"
		headers
		log 6 "Run_result: $run_result"
		[ ! "$REQUEST_METHOD" == "HEAD" -a -z "$redirected" ] && printf '%s\n' "$run_result"
	}
	
	# # TODO: Dunno if this is the right place for this.
	# # FIX:  The $(cmd-subst) creates a subshell around the entire run() function,
	# #       making any env vars created or modified by run() invisible at this point.
	# run | $(body=)
	# local body_length="$((${#body}))"
	# headers "$body_length"
	# printf '%s' "$body"
	
	# This final output is only appropriate when a body is returned,
	# but it is wrong for any reponses that are not supposed to have bodies (304, 307, etc..).
	#printf '\r\n\0'
	
	log 3 "${REQUEST_METHOD:-REQUEST_METHOD N/A} ${PATH_INFO:-PATH_INFO N/A} $STATUS"
	log 5 "End process_request"
} # Stdout returns to request handler, do not redirect.

# Reads stdin until first empty line.
# Picks up first line from $line, if defined.
# Returns result to stdout.
read_headers() {
	local line="${line:-''}"
	log 5 'Reading headers from stdin'
	log 6 '-echo "Reading headers from stdin with first line: $line"'
	while [ ! -z "$line" -a "$line" != $'\r' -a "$line" != $'\n' -a "$line" != $'\r\n' ]; do
		IFS= read -r line
		local input_headers="$input_headers""$line"$'\n'
	done
	log 6 '-echo "read_headers() ingested: $input_headers"'
	printf '%s' "$input_headers"
}

# Evaluates each legitimate line of env var declaration.
# Expects input on stdin or $1.
eval_input_env() {
	log 5 'Evaling input env vars'
	{
		local inpt=$(evalable_env_from_input "$1")
		set -a
		log 6 '-echo "Evaling input env vars: $inpt"'
		eval "$inpt"
		set +a
	} >&2
}

# Filters evalable shell env var(s) from stdin (var_name='anything-but-literal-single-quote').
# Does no modification of string.
# Expects input string on stdin (or $1) to be output from 'env' or 'export -p'.
# FIX: This breaks if any values contain an unescaped literal newline.
#      Literal new lines should be backslash-escaped.
evalable_env_from_input() {
	if [ -z "$1" ]; then
		cat -
	else
		printf '%s\n' "$1"
	fi |
	sed -ne "/^\(export \)\?[[:alnum:]_ ]\+='/,/[^']*'$/p"
}

# Converts line(s) of http header to env var declaration format: export VAR_NAME='<data>'.
# Expects input on $1.
# NOTE: Don't do this in a subshell from its caller, or it won't stick.
#
# TODO: This universal header parser seems to work now with http & scgi, but I haven't tried handle_cgi() yet.
# Also haven't tried the \r deletion yet.
# http_headers_to_env_var() {
# 	local inpt="$1"
# 	log 6 '-echo "http_headers_to_env_var receiving input: $inpt"'
# 	#local rslt=$( printf '%s' "$inpt" | tr -d '\r' | sed 's/^export *//' | tr -d "'" | \
# 	local rslt=$( printf '%s' "$inpt" | sed -e 's/^export *//' -e "s/'//g" -e "s/\r//g" | \
# 		\
# 		awk -F'=|: *' \
# 		    -v http_headers="$HTTP_STANDARD_HEADERS" \
# 		    -v http_prefix="$PREFIX_HTTP_STANDARD_HEADERS" \
# 				\
# 				' /^([[:alnum:]_-]+)(=|: *)(.+)$/ {
# 						gsub(/-/, "_", $1);
# 						$1 = toupper($1);
# 						if (http_prefix && match(http_headers, " "$1" ")) $1 = http_prefix"_"$1;
# 						print "export "$1"='\''"$2"'\''";
# 					}
# 				'
# 	)
# 	log 6 '-echo "Resulting env vars from http headers: $rslt"'
# 	#eval "$rslt"
# 	printf '%s' "$rslt"
# }
#
#
# # With awk multiple command blocks.
# 
# # See https://stackoverflow.com/questions/19154996/awk-split-only-by-first-occurrence
http_headers_to_env_var() {
	local inpt="$1"
	log 6 '-echo "http_headers_to_env_var receiving input: $inpt"'
	#local rslt=$( printf '%s' "$inpt" | tr -d '\r' | sed 's/^export *//' | tr -d "'" | \
	local rslt=$( printf '%s' "$inpt" | sed -e 's/^export *//' -e "s/'//g" -e "s/\r//g" | \
		\
		awk -F'=|: *' \
		    -v http_headers="$HTTP_STANDARD_HEADERS" \
		    -v http_prefix="$PREFIX_HTTP_STANDARD_HEADERS" \
				'
					/^[[:alnum:]_\-]+=.+$/ {
						sep = index($0, "=");
						val = substr($0,sep+1)
					}
				
					/^[[:alnum:]_\-]+:.+$/ {
						val_start = match($0, /: */) + RLENGTH;
						val = substr($0, val_start);
					}
				
					{
						gsub(/-/, "_", $1);
						$1 = toupper($1);
						if (http_prefix && match(http_headers, " "$1" ")) $1 = http_prefix"_"$1;
						print "export "$1"='\''"val"'\''";
					}
				'
	)
	log 6 '-echo "Resulting env vars from http headers: $rslt"'
	#eval "$rslt"
	printf '%s' "$rslt"
}

# Evals env returned from simple haserl call.
# No input, expects and uses exising env vars.
eval_haserl_env() {
	{
		log 5 '-echo "Evaling current env with haserl ($(get_pids))"'
		log 6 '-echo "Sending REQUEST_BODY to haserl stdin: $REQUEST_BODY"'
		haserl_env=$(printf '%s' "$REQUEST_BODY" | haserl "$HASERL_ENV")
		log 6 '-echo "Haserl env: $haserl_env"'
		set -a
		eval "$haserl_env"
		set +a
	} >&2
}

# Filters fifo-input env string, so it can be eval'd safely.
# Is intended to take output from 'env' and make it more like 'export -p'.
#   Escapes single-quotes first.
#   Adds a quote after '=' to any line that doesn't begin with a space or tab.
#   Adds a quote at end of any line that doesn't end with '\'.
# Taken from framework 'get_safe_fifo_input'
# Can take data on $1 or stdin
# NOTE: It's possible this may be obsolete. I don't think it's used any more.
# Before deleting this, make sure code-injection attacks are thwarted!
#
sanitize_var_declaration() {
	if [ -z "$1" ]; then cat; else echo "$1"; fi |
  sed "s/'/'\\\''/g; /^[^ \t]/{s/=/='/}; /[^\\]$/{s/$/'/}"
}

# Evals any given command+args and stores result in given var.
# Usage: eval_to_var <var-name> <command> [args...]
eval_to_var() {
	log 5 "Eval_to_var args: $*"
	local var_name="$1"
	
	shift
	log 5 '-echo "VAR: $var_name"'
	log 5 "CMD: $*"
	
	exec 15>&-
	exec 16>&-
	
	id=$(IFS='.' read -r up rest </proc/uptime; echo "$up")
	
	local fifo_in="/tmp/fifo_in_$id"
	local fifo_out="/tmp/fifo_out_$id"
	log 5 '-echo "FIFO: $fifo_in $fifo_out"'
	mkfifo "$fifo_in" "$fifo_out"
	eval "exec 15<>$fifo_in"
	eval "exec 16<>$fifo_out"
	
	local ss_pid=$(exec sh -c 'echo "$PPID"')
	log 6 '-echo "Eval_to_var FDs: $(ls -l /proc/$ss_pid/fd/)"'
	
	# Buffer runs in background and reads data into var from fifo,
	# then writes data out to fifo, so fifo won't block on their own buffer.
	#
	# This can be called as a function or as a simple command group,
	# as long as it is run in the background.
	#
	# The subshell wrapper prevents annoying output "[1]+  Done..."
	# after background process finishes.
	#
	(	#buffer &
		{
			log 5 "Subshelling fifo buffer helper"
			# This filter keeps the endofdata tag but discards further lines.
			local buf="$(sed '/__ENDOFDATA__/q' <&15)"
			exec 15>&-
			log 6 '-echo "BUF (0..16): ${buf:0:16} | head -n1"'
			printf '%s\n%s\n\n' "$buf" "__ENDOFDATA__" >&16
		} &
	)
		
	# Both \n\n are necessary or sed won't see the eof tag.
	{ eval "$*"; printf '\n%s\n\n' "__ENDOFDATA__"; } >&15
	log 6 "CMD sent data to fifo, now reading data into var '$var_name'"
	# This filter will discard the endofdata tag and all lines beyond it.
	local dat="$(sed -n '/__ENDOFDATA__/q;p' <&16)"$'\n'
		
	log 6 '-echo "DAT (0..16): ${dat:0:16}" | head -n1'
	eval "$var_name"'="$dat"'
	
	exec 15>&-
	exec 16>&-
	rm -f "$fifo_in" "$fifo_out"
	
	log 6 '-echo "VAR $var_name (0..16): ${'"$var_name"':0:16}" | head -n1'
}

# This is fabulous but is not currently used.
# Usage: $1 is in $2 ?
contains() {
    string="$2"
    substring="$1"
    #if test "${string#*$substring}" != "$string"; then
		if [ "${string/$substring/FALSE}" != "$string" ]; then
        return 0    # $substring is in $string
    else
        return 1    # $substring is not in $string
    fi
}

# Prints pids (current, parent, subshell). Show header row if $1 == true.
get_pids() {
	[ ! -z "$1" ] && echo -n "PID PPID sspid: "
	printf '%s' "$$ $PPID $(sspid)"
}

# Gets subshell PID. See https://unix.stackexchange.com/questions/484442/how-can-i-get-the-pid-of-a-subshell
sspid() {
	echo $(exec sh -c 'echo "$PPID"')
}

# uuid() {
# 	local length="${1:-16}"
# 	local overkill="${2:-8}"
# 	local raw_len=$(($length * $overkill))
# 	head -c "$raw_length" /dev/urandom | tr -dc 'a-zA-Z0-9' | cut -c 0-$(($length))
# }

# # Passes stdin (env list) to daemon via fifo,
# # Receives response via private fifo.
# call_daemon_with_fifo() {
# 	log 5 "Sending data as env vars to app daemon with fifo $FIFO_INPUT ($$)"
# 	{
# 		local fifo_output="${FIFO_OUTPUT}_$$"
# 		cat -
# 		printf '%s\n' "export FIFO_OUTPUT='$fifo_output'"
# 		mkfifo "$fifo_output" >&2 #>/tmp/log_102
# 	} >"$FIFO_INPUT"
# 	
# 	# Receive and cleanup fifo-output.
# 	log 5 "Waiting for return data app daemon via fifo $fifo_output"
# 	cat "$fifo_output" &&
# 	rm -f "$fifo_output" >&2
# 	log 5 "Received response from app daemon via fifo $fifo_output"
# }

# Runs the daemon and socat processes in paralell
start_server() {
	#echo "$(date -Iseconds) Running the Haserl Framework Server v0.0.1"
	# Spawn a subshell, otherwise we'll kill the main shell.
	# TODO: Consider using start-stop-daemon.
	echo "$$" > "$PID_FILE"
	log 4 'Starting HF server'
	# Note the 5th field in /proc/<pid>/stat is the pgid.
	
	#( daemon_server | socat_server ) &
	
	log 3 "Haserl Framework Server v0.0.1, log-level $LOG_LEVEL, ($(get_pids))"
	#echo "TESTING /tmp/log_103" >/tmp/log_103
	#echo "TESTING fd 102" >&102
	#echo "TESTING logger stdin" | log 3
	#log 5 "PID $$"
	#log 5 "FD's for pid $$ $(ls -l /proc/$$/fd/ | awk '{print $9,$10,$11}')"
	#echo "Test stderr... >&2" >&2
	
	if [ "$1" == 'console' ]; then
		while :; do IFS= read -r line; eval "$line"; done
	elif [ "$1" == 'daemon' ]; then
		
		# Manually, you can do this, from the command line:
		# (LOG_LEVEL=3 ./app.sh 0</dev/null 1>daemon.log 2>&1) &
		
		# But the rest of this doesn't work yet: Can't seem to detach output from terminal.
		
		#( socat_server | request_loop ) 22>>daemon.log 1>&22 2>&22 &
				
		# TRY THIS. It puts the current process in the background.
		(kill -STOP $$; kill -CONT $$) >/dev/null 2>&1 &
		sleep 1
		
		1>&22
		exec 0<&-
		
		( socat_server | request_loop )
	else
		#while :; do sleep 60; done
		#daemon_server | socat_server
		#request_loop | socat_server
		# Without the pipe 'holding' socat_server in the background, endless loop will occur in trap (from ctrl-c, exit...)
		#socat_server | request_loop
		socat_server | handle_socat_loop
	fi
}

stop_server() {
	kill -15 -"$(cat $PID_FILE)"
}

initialize() {
	# Sets up fifo files.
	log 6 'Setting up fifo files.'
	rm -f "$FIFO_INPUT" "$FIFO_OUTPUT" "$FIFO_TOKEN"
	rm -f "$FIFO_INPUT" "$FIFO_OUTPUT" "$FIFO_TOKEN"
	mkfifo "$FIFO_INPUT" "$FIFO_OUTPUT" "$FIFO_TOKEN"
	rm -f /tmp/hf_*

	# Sets up the haserl template file.
	printf '%s' "<% export -p %>" > "$HASERL_ENV"
	
	log 6 '-echo "Recognizing http-headers: $HTTP_STANDARD_HEADERS"'

	#export -p >&2 # TEMP DEBUGGING
	
	export HF_SERVER_INITIALIZED=true
}

# See this for signal listing - https://unix.stackexchange.com/questions/317492/list-of-kill-signals
trap 'cleanup_logging; handle_trap' 1 2 3 4 6 15

# Handles cleanup when the application quits.
handle_trap(){
	echo "Running handle_trap for $(get_pids)"
	rm -f "$HASERL_ENV" "$FIFO_INPUT" "$FIFO_OUTPUT" "$FIFO_TOKEN" "$fifo_output" /tmp/hf_fifo*
	local pid="$(cat $PID_FILE)"
	rm -f "$PID_FILE"
	printf '\n%s\n' "Goodbye!"
	kill -9 -"${pid:-$$}"
} >&22

initialize

#( $* )

# # Going to get rid of this. Nothing wrong with it, just trying to simplify.
# # Handles runtime/startup command processing
# case $1 in
# 	"start")
# 		initialize && start_server $2
# 		;;
# 	"stop")
# 		stop_server $2
# 		;;
# 	# "handle")
# 	# 	handle_request $2
# 	# 	;;
# 	# "console")
# 	# 	start_server 'console'
# 	# 	;;
# 	# "daemon")
# 	# 	start_server 'daemon'
# 	# 	;;
# 	*) # else
# 		initialize &*
# 		;;
# esac


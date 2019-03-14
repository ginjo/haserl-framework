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


export FIFO_INPUT="${FIFO_INPUT:=/tmp/fifo_input}"
export FIFO_OUTPUT="${FIFO_OUTPUT:=/tmp/fifo_output}"
export HASERL_ENV="${HASERL_ENV:=/tmp/haserl_env}"
export PID_FILE="${PID_FILE:=/tmp/hf_server.pid}"
export HF_DIRNAME="${HF_DIRNAME:=$(dirname $0)}"
export HF_SERVER="${HF_SERVER:=$HF_DIRNAME/server.sh}"
export HF_LISTENER="${HF_LISTENER:=tcp-l:1500,reuseaddr}"
export HF_LISTENER_OPTS="${HF_LISTENER_OPTS:=-d -t0.2 -T60}"

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
		#socat -d -t1 -T5 $HF_LISTENER exec:"${HF_SERVER} handle"
		#socat -d -t1 -T10 $HF_LISTENER system:'cat - >"$FIFO_INPUT" | cat "$FIFO_OUTPUT"'
		#socat -d -t10 tcp-l:1500,reuseaddr,fork STDIO <"$FIFO_INPUT" | handle_request >"$FIFO_INPUT"
		
		# Forking socat with dual fifo files to/from request_loop. This works well.
		# The shut-null on addr1, combined with subshelling the handle_request call, is necessary
		# for redirects to work properly with this style of socat (forking with STDIO).
		# The shut-null on addr2 is experimental. The null-eof's are both experimental.
		# The keepalive doesn't seem to help redirects use keepalive.
		socat $HF_LISTENER_OPTS $HF_LISTENER,fork,shut-null,null-eof,keepalive STDIO,shut-null,null-eof 1>"$FIFO_INPUT" 0<"$FIFO_OUTPUT"
		
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
		# 	socat $HF_LISTENER_OPTS $HF_LISTENER STDIO <"$fifo" | handle_request >"$fifo"
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

request_loop() {
	# FIX: There is a race condition somewhere in the loop,
	# that causes all 1+n requests to hang at the beginning.
	# The issue that was recently fixed was a couple extra chrs
	# leftover in the input pipe, clogging up handle_request().
	# TODO: Improve initial-character read and inspection,
	# and add a rule to the if/else conditions at beginning
	# of list handle_request().
	#   Drop any non-alnum characters at beginning
	# Don't forget to adjust the temp fix put in place 
	# at the time of this writing (2019-03-07T01:35:00-PST). (which was...?)
	exec 0<"$FIFO_INPUT"
	log 4 '-echo "Starting request loop listener ($(get_pids))"'

	while [ $? -eq 0 ]; do
		log 5 "Begin request loop"
		
		( # This is where the request is currently subshelled, to protect the main server env.
		  # It may not be necessary to subshell, however, since the entire script-run may be
		  # in a subshell, if it's running as the last part of a pipe. Check all your pipes.
			# NOTE: This subshelling appears to be really IMPORTANT for redirected requests to work,
			# when using the forking socat with STDIO. Also see the socat options necessary,
			# like short '-t' and shut-null on addr1
			
			# Provides gating so upstream processes aren't started unnecessarily.
			# TODO: Try moving this outside the subshell again, and open stdout at beginning of 'while'
			# Then see if you can background the subshell.
			log 5 '-echo "Waiting for request on $FIFO_INPUT"'
			IFS= read -rn1 chr
			if [ "${chr/[^a-zA-Z1-9_]/DROP}" == 'DROP' ]; then
				log 3 "Unexpected character ($chr) received at beginning of request loop ($(get_pids))"
				continue
			fi
			log 5 '-echo "Read $chr from $FIFO_INPUT, sending control to handle_request"'
			
			# Manually opens stdout to fifo.
			#exec 1>"$FIFO_OUTPUT"
			
			handle_request "$chr" #>"$FIFO_OUTPUT"
			# Not clear if this EOF helps or not.
			printf '\0' #>"$FIFO_OUTPUT"
					
			# Manually closes stdout to fifo.
			#exec 1>&-
		
			# The pause is needed to keep a race condition from happening,
			# when the loop begins again to quickly. Hasn't been needed in awhile.
			#sleep 1

		) >"$FIFO_OUTPUT"
		
		log 5 "End request loop"
	done
	log 2 '-echo "Leaving request loop listener ($(get_pids)) exit code ($?)"'
	
	# Just to be safe, cleanup if the loop breaks or ends.
	exec 1>&-
	exec 0<&-
}

# Handles request from socat server.
# Expects data to be on stdin.
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
		elif printf '%s' "$line" | grep -qE '^(export )?[[:alnum:]_]+='; then
			log 5 '-echo "Calling handle_cgi with ($line)"'
			handle_cgi "$line"
			#break
		elif printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE).*HTTP'; then
			log 5 '-echo "Calling handle_http with ($line)"'
			handle_http "$line"
			#break
		else
			log 6 '-echo "No handler found yet for request beginning with:$line"'
			continue
		fi
		
		# If you made it this far, you've completed a request.
		break
		
		# This doesn't help multiple requests (on same connection),
		# since it eventually hangs on reading fifo with nothing to offer.
		# log 5 'Resetting handle_request and waiting for another (only with keep-alive)'
		# line=
		# chr=
	done
	log 5 "End handle_request"
	
	local end_time="$(timer)"
	local elapsed_time=$(echo "$start_time $end_time" | awk '{print $2 - $1}')
	log 4 '-echo "Elapsed ${elapsed_time}s Start $start_time End $end_time"'
} # Stdout should go back to socat server. Do not redirect.

# The handler processes the input from socat and sends it to the daemon via fifo.
# This accepts and handles http and non-http input containing env code (cgi).
# TODO: Refactor this function & split it into two (http, cgi).
#
handle_http(){
	log 5 "Begin handle_http/handle_cgi with '$1' ($(get_pids))"
	# All stdout in this block gets sent to process_request()
	inpt=$({
		local line=''
		local len=0
		IFS= read -r line
		local first_line="$1$line"
		
		log 6 "FIRST-LINE: $first_line"
		printf '%s\n' "$first_line"

		if printf '%s' "$first_line" | grep -qE '^(GET|POST|PUT|DELETE)'; then
		# If this is a valid http request, ingest it as such...
			# This should probably be a custom env var like HTTP_REQUEST,
			# then parse that in its own function, or in the framework, or in process_request()
			export PATH_INFO=$(echo "$first_line" | sed 's/^[[:alpha:]]\+ \([^ ]\+\) .*$/\1/')
			log 5 "Reading raw http (or cgi) headers from stdin."
			while [ ! -z "$line" -a "$line" != $'\r' -a "$line" != $'\n' -a "$line" != $'\r\n' ]; do
				IFS= read -r line
				[ -z "${line/Content-Length:*/}" ] && len="${line/Content-Length: /}"
				printf '%s\n' "$line"
			done
			if [ $(($len)) > 0 ]; then
				log 6 '-echo "Calling head on stdin with -c $len"'
				head -c $(($len))
			fi
		else # If this is just a list of env vars...
			log 5 "Reading cgi input (env vars) from stdin."
			# FIX: This doesn't ever return now.
			#cat #| tee /tmp/log_106
			
			# This is necessary, because otherwise reading from stdin hangs.
			# This happens when pushing env vars from a cgi script to this app
			# using nc, socat, or directlly via fifo.
			# If receiving these cgi/haserl requests over the socat interface,
			# you may also need to adjust -t and -T on that interface using $HF_LISTENER_OPTS.
			socat -u -T0.2 - -
		fi
		
		export -p
		
		# NOTE: The pipe chain is stopped and restarted here (and above, see 'inpt'),
		# otherwise the response gets back to the client before
		# the data can be processed, and the client disconnects.
	}) #| process_request
	
	log 5 'Calling process_request with cgi input'
	echo "$inpt" | process_request
	
	log 5 "End handle_http/handle_cgi"
} # Stdout goes back to socat server. Do not redirect.

#alias handle_cgi='handle_http()'
handle_cgi() { handle_http "$@"; }
#alias handle_cgi='handle_http'

# Accepts and parses SCGI input on stdin, and sends it to process_request.
# Respons from process_request is returned on stdout to upstream handle_request.
# This function expects $1 containing the total num of characters in the scgi headers.
handle_scgi() {
	log 5 "Begin handle_scgi with '$1' ($(get_pids))"
	#log 6 '-ls -la /proc/$$/fd'
	{
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
		)
		
		# Drops the last 2 chrs from stdin (I think they were ' ,')
		# TODO: Is the request body being damaged by this? YES!
		# TODO: Find a less hacky place/way to do this.
		#dd count=1 bs=2 >/dev/null 2>&106
		# There is still a comma being left over. Try dropping it.
		# This works, but...
		# TODO: Make sure this works with POST containing body text.
		#local dropped_chr=$(dd count=1 bs=1 2>/dev/null)
		IRS= read -rn1 dropped_chr
		log 6 '-echo "Dropped ($dropped_chr) from end of scgi input"'
		
		log 6 '-echo "Parsed SCGI headers $scgi_headers"'
		
		# Extracts CONTENT_LENGTH value from scgi_headers and evals it into a var.
		local content_length_header=$(echo "$scgi_headers" | grep '^CONTENT_LENGTH')
		log 6 '-echo "Scgi body content length declaration $content_length_header"'
		eval "$content_length_header"
	
		# Gets remaining stdin containing request body, if exists.
		if [ $(($CONTENT_LENGTH)) -gt 0 ]; then
			log 5 '-echo "Reading $CONTENT_LENGTH more chars as request body"'
			export REQUEST_BODY=$(dd count=$(($CONTENT_LENGTH)) bs=1 skip=1 2>&106)
			#echo "Request body: $REQUEST_BODY"
		fi
		
		# All stdout from this grouping should go to log.
	} >&2 #>/tmp/log_103  #>&103
	
	# Outputs scgi env and local env to process_request.
	log 5 "Printing scgi_headers and exported env to process_request"
	{
		printf '%s\n' "$scgi_headers"
		export -p
	} | process_request
	
	log 5 "End handle_scgi"
} # Stdout goes back to socat server. Do not redirect.

# Parse & eval the request env, and call the framework action(s).
# Stdout will be sent back to request handler.
# Expects a LF delimited list of env variable definitions with single-quoted data, on stdin.
# Example: export MY_VAR='hey there'
process_request() {
	log 5 '-echo "Begin process_request ($(get_pids))"'
	#local input_env="$(cat -)"
	
	eval_input_env #"$input_env"
	unset TERMCAP
	eval_haserl_env
	log 6 '-echo "Calling run() with env: $(env)"'

	# TODO: Put a conditional here that controls whether or not
	# to send the status header. You would only send it, if you
	# are receiving http requests directly from the client, with
	# no front-end web server.
	# Should this go in the handle_http funtion?
	#printf '%s\r\n' "HTTP/1.1 200 OK"
	# But does this really belong here?
	if echo "$GATEWAY_INTERFACE" | grep -qv '^CGI' && [ ! "$SCGI" == '1' ]; then
		printf '%s\n' "HTTP/1.0 200 OK"
	fi
	
	run
	
	log 3 "${REQUEST_METHOD:-REQUEST_METHOD N/A} ${REQUEST_URI:-REQUEST_URI N/A}"
	log 5 "End process_request"
}

# Filters input for only single-quoted safely eval'able var definitions,
# then evals each of those lines.
# Expects input on stdin.
eval_input_env() {
	log 5 '-echo "Evaling input env vars ($(get_pids))"'
	{
		#local evalable_input=$(evalable_env_from_input "$1")
		set -a
		#eval "$evalable_input"
		eval "$(evalable_env_from_input)"
		set +a
	} >&2
}

# Filters evalable env code from stdin (var='anything-but-literal-single-quote').
# Does no modification of string.
# Expects input string on stdin to be output from 'env' or 'export -p'.
evalable_env_from_input() {
	#echo "$1" | sed -ne "/^\(export \)\?[[:alnum:]_ ]\+='/,/[^']*'$/p"
	sed -ne "/^\(export \)\?[[:alnum:]_ ]\+='/,/[^']*'$/p"
}

# Evals env returned from simple haserl call.
# No input, execpts exising env vars.
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
sanitize_var_declaration() {
	if [ -z "$1" ]; then cat; else echo "$1"; fi |
  sed "s/'/'\\\''/g; /^[^ \t]/{s/=/='/}; /[^\\]$/{s/$/'/}"
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
		socat_server | request_loop
	fi
}

stop_server() {
	kill -15 -"$(cat $PID_FILE)"
}

initialize() {
	# Sets up fifo files.
	log 6 'Setting fifo in/out files.'
	rm -f "$FIFO_INPUT" "$FIFO_OUTPUT"
	rm -f "$FIFO_INPUT" "$FIFO_OUTPUT"
	mkfifo "$FIFO_INPUT" "$FIFO_OUTPUT"
	rm -f /tmp/hf_fifo*

	# Sets up the haserl template file.
	printf '%s' "<% export -p %>" > "$HASERL_ENV"

	#export -p >&2 # TEMP DEBUGGING
	
	export HF_SERVER_INITIALIZED=true
}

# See this for signal listing - https://unix.stackexchange.com/questions/317492/list-of-kill-signals
trap 'cleanup_logging; handle_trap' 1 2 3 4 6 15

# Handles cleanup when the application quits.
handle_trap(){
	echo "Running handle_trap for $(get_pids)"
	rm -f "$HASERL_ENV" "$FIFO_INPUT" "$FIFO_OUTPUT" "$fifo_output" /tmp/hf_fifo*
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


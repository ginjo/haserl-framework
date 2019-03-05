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

export FIFO_INPUT="${FIFO_INPUT:=/tmp/fifo_input}"
export FIFO_OUTPUT="${FIFO_OUTPUT:=/tmp/fifo_output}"
export HASERL_ENV="${HASERL_ENV:=/tmp/haserl_env}"
export PID_FILE="${PID_FILE:=/tmp/hf_server.pid}"
export HF_DIRNAME="${HF_DIRNAME:=$(dirname $0)}"
export HF_SERVER="${HF_SERVER:=$HF_DIRNAME/server.sh}"
export HF_LISTENER="${HF_LISTENER:=tcp-l:1500,reuseaddr,fork}"

. "$HF_DIRNAME/logging.sh"

#export -p >&2 # TEMP DEBUGGING

# See this for signal listing - https://unix.stackexchange.com/questions/317492/list-of-kill-signals
trap 'cleanup_logging; handle_trap' 1 2 3 4 6   #15

# Handles cleanup when the application quits.
handle_trap(){
	log 5 "Running handle_trap for $$"
	rm -f "$HASERL_ENV" "$FIFO_INPUT" "$FIFO_OUTPUT" "$fifo_output"
	#kill -9 $sd
	#kill -15 -$$
	#kill -15 -"$(cat $PID_FILE)"
	rm -f "$PID_FILE"
	printf '\n%s\n' "Goodbye!"
	kill -15 -$$
}

# Simple daemon paired with socat tcp interface.
# Note that the fifo input and fifo output need to be two separate commands,
# not piped (paralell processing), even if they use the same fifo,
# or they will block each other.
# Bad: cat fifo_in | some_command > fifo2
# Better: input="$(cat fifo1)"; echo "$input" > fifo2
# The same goes for the socat instance that is writing & reading to/from this daemon.
#
# The daemon is the part that receives the raw env code from the cgi/scgi env
# and processes the framework request.
#
# Expects a lf delimited list of env variable definitions with single-quoted data.
# Example: export MY_VAR='hey there'
#
daemon_server() {
	rm -f "$FIFO_INPUT" "$FIFO_OUTPUT"
	mkfifo "$FIFO_INPUT" "$FIFO_OUTPUT"
	chmod 600 "$FIFO_INPUT" "$FIFO_OUTPUT"
	printf '%s' "<% export -p %>" > "$HASERL_ENV"
	
	log 4 "Starting application server ($$)"
	
	while [ $? -eq 0 ]; do
		# Forks a subshell to keep each request environment separate.
		local input_env="$(cat $FIFO_INPUT)"
		log 5 "Begin request loop"
		(	
			
			# If there are ANY errors in this subshell, exit the subshell and go back to top of loop.
			# At that point, the while-loop will stop and the daemon_server will return.
			# Not sure if that's what we want, but this was created this way to prevent runaway while-loop.
			#set -e
			
			eval_input_env "$input_env"
			
			# echo "Daemon evaled env, before haserl:" >&2
			# export -p >&2
			
			unset TERMCAP
			eval_haserl_env
			
			# echo "Daemon evaled env, after haserl:" >&2
			# export -p >&2
			
			# Outputs the response to the fifo-output (possibly specific to this subshell).
			# The upstream caller should know how to find the correct FIFO_OUTPUT file.
			# NOTE: Do not send raw status back to CGI. Instead, send it like a header: 'Status: 200 OK'
			#       CGI will create the http status line for you!
			{
				# Returns basic headers for cgi/haserl script.
				# printf '%s\r\n' "Status: 200"
				# printf '%s\r\n' "Content-Type: text/plain"
				# 			  printf '%s\r\n' "Date: $(date)"
				# printf '%s\r\n' "Frontend-Server: $HTTP_HOST"
				# 			  printf '%s\r\n' "Backend-Server: $SOCAT_SOCKADDR:$SOCAT_SOCKPORT"
				# 			  printf '%s\r\n' "Client: $SOCAT_PEERADDR:$SOCAT_PEERPORT"
				# printf '%s\r\n'
				# export -p
				
				run
				
			} > "$FIFO_OUTPUT"
			
			log 5 "End request loop"
			log 3 "$REQUEST_METHOD $REQUEST_URI"
			
		) &
	done
}

# The socat process takes input over tcp (or sockets),
# and sends it to the daemon via two fifo pipes.
# To keep the socat 'system' call simple, a handler function is called.
#
# Note that when socat 'system' call is reading an http request from stdinl,
# you need to look at content type and specify exactly how many bytes to read.
# Otherwise, the read/head/cat/whatever command will hang on stdin, waiting
# for the client to send more data.
#
# Note that the hang-on-stdin doesn't happen when data is received from a
# low-level tcp client like nc, ncat, or socat (because they are not http clients).
#
# Note that if -t is too small, the pipe will break before 'system' call is finished.
#
socat_server(){
	{
		#echo "Starting socat_server with handler (${1:-<undefined>})" >&2
		log 4 "Starting socat with HF_LISTENER '$HF_LISTENER' ($$)"
		#socat -t5 tcp-l:1500,reuseaddr,fork system:". socat_server.sh && handle_http",nonblock=1    #,end-close
		# TODO: Allow server startup command to pass socat options and 1st addr to this command.
		#socat -d -t1 -T5 tcp-l:1500,reuseaddr,fork system:". ${HF_DIRNAME}/server.sh && handle_${1:-cgi}",nofork
		#socat -d -t0.2 -T5 tcp-l:1500,reuseaddr,fork exec:"${HF_SERVER} handle ${1:-scgi}"
		socat -d -t1 -T5 $HF_LISTENER exec:"${HF_SERVER} handle"
	} >&105 2>&1  # Othwerwise, socat spits out too much data.
}

# Handles request from socat server.
handle_request() {
	log 5 "Begin handle_request ($$)"
	local line=''
	local chr=''
	while :; do  #[ "$?" == "0" ]; do
		#chr=$(dd count=1 bs=1 2>/dev/null)
		IFS= read -rn1 chr
		echo "Reading request chr: $chr" >&106
		line="$line$chr"
		log 6 "Choosing handler for request beginning with: $line"
		if printf '%s' "$line" | grep -qE '^[0-9]+:'; then
			log 5 "Calling handle_scgi with $line"
			handle_scgi "$line"
			break
		elif printf '%s' "$line" | grep -qE '^(export )?[[:alnum:]_]+='; then
			log 5 "Calling handle_cgi with $line"
			handle_cgi "$line"
			break
		elif printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE).*HTTP'; then
			log 5 "Calling handle_http with $line"
			handle_http "$line"
			break
		else
			log 6 "No handler found yet for request beginning with: $line"
		fi
	done
	log 5 "End handle_request"
} # Stdout goes back to socat server. Do not redirect.

# The handler processes the input from socat and sends it to the daemon via fifo.
# This accepts and handles http and non-http input containing env code
#
handle_http(){
	log 5 "Begin handle_http/handle_cgi with '$1' ($$)"
	{
		local line="x"
		local len=0

		read line
		log 6 "FIRST-LINE: $line"
		printf '%s%s\n' "$1" "$line"
		if printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE)'; then
		# If this is a valid http request, ingest it as such...
			log 5 "Reading raw http headers from stdin."
			printf '%s\n' "$line"
			while [ ! -z "$line" -a "$line" != $'\r' -a "$line" != $'\n' -a "$line" != $'\r\n' ]; do
				read line
				[ -z "${line/Content-Length:*/}" ] && len="${line/Content-Length: /}"
				printf '%s\n' "$line"
			done
			if [ $(($len)) > 0 ]; then
				log 6 "Calling 'head' on stdin with -c $len"
				head -c $(($len))
			fi
		else # If this is just a list of env vars...
			log 6 "Calling 'cat' on stdin"
			cat -
		fi
		
		export -p
		
	} | call_daemon_with_fifo
	
	log 5 "End handle_http/handle_cgi"
} # Stdout goes back to socat server. Do not redirect.

#alias handle_cgi='handle_http()'
handle_cgi() { handle_http $*; }

# Accepts and parses SCGI input, and sends it to call_daemon_with_fifo.
# This function expects $1 containing the total num of characters in the scgi headers.
handle_scgi() {
	log 5 "Begin handle_scgi with '$1' ($$)"
	{
		# Arg $1 contains the total length of headers.
		# Gets all but the last character of $1 (last chr is a ':', which we don't want).
		local len="${1:0:$((${#1}-1))}"
		
		log 5 "Reading $len characters of scgi input."
	
		# Reads header length, reads headers, translates into env var code.
		local scgi_headers=$(
			dd count=$(($len)) bs=1 2>/dev/null |
			tr '\0' '\n' |
			sed '$!N;'"s/\n/='/;s/$/'/"
		)
		log 6 '-echo "SCGI headers $scgi_headers"'
		
		# Extracts CONTENT_LENGTH from scgi_headers and evals it into a var.
		local content_length_var=$(echo "$scgi_headers" | grep '^CONTENT_LENGTH')
		log 6 "Scgi body content length declaration $content_length_var"
		eval "$content_length_var"
	
		# Gets remaining stdin containing request body, if exists.
		if [ $(($CONTENT_LENGTH)) -gt 0 ]; then
			log 5 "Reading $CONTENT_LENGTH more chars as request body."
			export REQUEST_BODY=$(dd count=$(($CONTENT_LENGTH)) bs=1 skip=1 2>/dev/null | tee -a scgi_input.txt)
			#echo "Request body: $REQUEST_BODY"
		fi
		
		# All stdout from this grouping should go to log.
	} >&2 #>/tmp/log_103  #>&103
	
	# Outputs scgi env and local env to call_daemon_with_fifo.
	{
		printf '%s\n' "$scgi_headers"
		export -p
	} | call_daemon_with_fifo
	
	log 5 "End handle_scgi"
} # Stdout goes back to socat server. Do not redirect.

# Filters input for only single-quoted safely eval'able var definitions,
# then evals each of those lines.
# Expects input as $1
eval_input_env() {
	log 5 "Evaling input env vars ($$)"
	{
		evalable_input=$(evalable_env_from_input "$1")
		set -a
		eval "$evalable_input"
		set +a
	} >&2
}

# Returns evalable env code from stdin.
# Expects input string on $1.
evalable_env_from_input() {
	echo "$1" | sed -ne "/^\(export \)\?[[:alnum:]_ ]\+='/,/[^']*'$/p"
}

# Evals env returned from simple haserl call.
eval_haserl_env() {
	{
		log 5 "Evaling env with haserl ($$)"
		log 6 "Sending REQUEST_BODY to haserl:"
		log 6 '-echo "$REQUEST_BODY"'
		haserl_env=$(printf '%s' "$REQUEST_BODY" | haserl "$HASERL_ENV")
		log 6 '-echo "Haserl env: $haserl_env"'
		set -a
		eval "$haserl_env"
		set +a
	} >&2
}

# Passes stdin (env list) to daemon via fifo,
# Receives response via private fifo.
call_daemon_with_fifo() {
	log 5 "Sending data as env vars to app daemon with fifo $FIFO_INPUT ($$)"
	{
		local fifo_output="${FIFO_OUTPUT}_$$"
		cat -
		printf '%s\n' "export FIFO_OUTPUT='$fifo_output'"
		mkfifo "$fifo_output" >&2 #>/tmp/log_102
	} >"$FIFO_INPUT"
	
	# Receive and cleanup fifo-output.
	log 5 "Waiting for return data app daemon via fifo $fifo_output"
	cat "$fifo_output" &&
	rm -f "$fifo_output" >&2
	log 5 "Received response from app daemon via fifo $fifo_output"
}

# Runs the daemon and socat processes in paralell
start_server() {
	#echo "$(date -Iseconds) Running the Haserl Framework Server v0.0.1"
	# Spawn a subshell, otherwise we'll kill the main shell.
	# TODO: Consider using start-stop-daemon.
	#echo "$$" > "$PID_FILE"
	log 4 'Starting HF server'
	# Note the 5th field in /proc/<pid>/stat is the pgid.
	
	#( daemon_server | socat_server ) &
	
	log 3 "Haserl Framework Server v0.0.1, log-level $LOG_LEVEL, ($$)"
	#echo "TESTING /tmp/log_103" >/tmp/log_103
	#echo "TESTING fd 102" >&102
	#echo "TESTING logger stdin" | log 3
	#log 5 "PID $$"
	#log 5 "FD's for pid $$ $(ls -l /proc/$$/fd/ | awk '{print $9,$10,$11}')"
	#echo "Test stderr... >&2" >&2
	if [ "$1" == 'console' -o "$HF_CONSOLE" == 'true' ]; then
		while :; do IFS= read -r line; eval "$line"; done
	elif [ "$1" == 'daemon' ]; then
		#( while :; do sleep 60; done ) 0</dev/null 1>&0 2>&0 &
		
		# (
		# 	echo "$$" > "$PID_FILE"
		# 	exec 0<&-
		# 	exec 1>/dev/null
		# 	exec 2>&1
		# 	daemon_server | socat_server
		# ) >/dev/null 2>&1 0<&- &
		
		exec 0</dev/null
		exec 22>daemon.log
		
		(daemon_server | socat_server) &
		
		# TRY THIS:
		(echo "$$" > "$PID_FILE"; kill -STOP $$; kill -CONT $$) &
		sleep 1
	else
		#while :; do sleep 60; done
		daemon_server | socat_server
	fi
}

stop_server() {
	kill -15 -"$(cat $PID_FILE)"
}

# Handles runtime/startup command processing
log 5 "Running server case statement with args: $@"
case $1 in
	"start")
		start_server $2
		;;
	"stop")
		stop_server $2
		;;
	"handle")
		handle_request $2
		;;
	"console")
		start_server 'console'
		;;
	"daemon")
		start_server 'daemon'
		;;
esac


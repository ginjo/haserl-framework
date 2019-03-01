#!/bin/sh

export FIFO_INPUT="${FIFO_INPUT:=/tmp/fifo_input}"
export FIFO_OUTPUT="${FIFO_OUTPUT:=/tmp/fifo_output}"
export HASERL_ENV="${HASERL_ENV:=/tmp/haserl_env}"
export SOCAT_SERVER_PID="${SOCAT_SERVER_PID:=/tmp/socat_server.pid}"
export HF_DIRNAME="${HF_DIRNAME:=$(dirname $0)}"
export HF_SERVER="${HF_SERVER:=$HF_DIRNAME/server.sh}"

. "$HF_DIRNAME/logging.sh"

# See this for signal listing - https://unix.stackexchange.com/questions/317492/list-of-kill-signals
trap 'cleanup_logging; handle_trap' 1 2 3 4 6   #15

# Handles cleanup when the application quits.
handle_trap(){
	log 4 "Running handle_trap $$"
	rm -f "$HASERL_ENV" "$FIFO_INPUT" "$FIFO_OUTPUT" "$fifo_output"
	#kill -9 $sd
	#kill -15 -$$
	#kill -15 -"$(cat $SOCAT_SERVER_PID)"
	rm -f "$SOCAT_SERVER_PID"
	printf '\n%s\n' "Goodbye!" >&2
	kill -15 -$$
}

# Runs the daemon and socat processes in paralell
main_server() {
	#echo "$(date -Iseconds) Running the Haserl Framework Server v0.0.1"
	log 3 "Starting the Haserl Framework Server v0.0.1 with log-level ($LOG_LEVEL)"
	# Spawn a subshell, otherwise we'll kill the main shell.
	# TODO: Consider using start-stop-daemon.	
	(
		echo "$$" > "$SOCAT_SERVER_PID"
		log 4 'Running main_server'
		# Note the 5th field in /proc/<pid>/stat is the pgid.
	
		# daemon_server &
		# sd="$!"
		# socat_server  #&
		# #ss="$!"
		# wait $sd #$ss
		
		daemon_server | socat_server $1
	)
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
	
	log 4 'Starting daemon_server'
	
	while [ $? -eq 0 ]; do
		# Forks a subshell to keep each request environment separate.
		local input_env="$(cat $FIFO_INPUT)"
		log 5 "Begin daemon loop"
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
			
			log 3 "$REQUEST_METHOD $REQUEST_URI"
			
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
			log 5 "End daemon loop"
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
		echo "Running socat_server with handler (${1:-<undefined>})"
		#socat -t5 tcp-l:1500,reuseaddr,fork system:". socat_server.sh && handle_http",nonblock=1    #,end-close
		# TODO: Allow server startup command to pass socat options and 1st addr to this command.
		#socat -d -t1 -T5 tcp-l:1500,reuseaddr,fork system:". ${HF_DIRNAME}/server.sh && handle_${1:-cgi}",nofork
		socat -d -t0.2 -T5 tcp-l:1500,reuseaddr,fork exec:"${HF_SERVER} handle ${1:-scgi}" 2>&103
	} >&104
}

# The handler processes the input from socat and sends it to the daemon via fifo.
# This accepts and handles http and non-http input containing env code
#
handle_http(){
	log 5 'Running handle_http/handle_cgi'
	{
		local line="x"
		local len=0

		read line
		#echo "FIRST-LINE: $line" >&2
		printf '%s\n' "$line"
		if printf '%s' "$line" | grep -qE '^(GET|POST|PUT|DELETE)'; then
		# If this is a valid http request, ingest it as such...
			#echo "Reading raw http headers from stdin." >&2
			printf '%s\n' "$line"
			while [ ! -z "$line" -a "$line" != $'\r' -a "$line" != $'\n' -a "$line" != $'\r\n' ]; do
				read line
				[ -z "${line/Content-Length:*/}" ] && len="${line/Content-Length: /}"
				printf '%s\n' "$line"
			done
			if [ $(($len)) > 0 ]; then
				#echo "Calling 'head' on stdin with -c $len" >&2
				head -c $(($len))
			fi
		else # If this is just a list of env vars...
			#echo "Calling 'cat' on stdin." >&2
			cat -
		fi
		
		export -p
		
	} | call_daemon_with_fifo
	log 5 "End handle_http/handle_cgi"
}

#alias handle_cgi='handle_http'
handle_cgi() { handle_http $*; }

# Accepts and parses SCGI input, and sends it to call_daemon_with_fifo.
handle_scgi() {
	log 5 "Begin handle_scgi"
	{
		local len=''
		local chr=''
		
		# Reads first characters of scgi input, until <colon> or <space>,
		# and uses them to build the header-length integer.
		while echo "$chr" | grep -qv '[ \:]' ; do
			#echo "CHR: $chr" >&2
			len="$len$chr"
			read -rn1 chr
		done
		
		# Opens stdin for reading (and keeps it open).
		# This does not appear to be necessary at the moment.
		#exec 0<&0
		
		log 5 "Reading $len characters of scgi input."
	
		# Reads header length, reads headers, translates into env var code.
		scgi_headers=$(
			dd count=$(($len)) bs=1 2>/dev/null |
			tr '\0' '\n' |
			sed '$!N;'"s/\n/='/;s/$/'/"
		)
		
		# Sets var to content length of request body.
		eval $(echo $scgi_headers | sed 's/^\(CONTENT_LENGTH\):/\1=/')
	
		# Gets remaining stdin containing request body, if exists.
		if [ $(($CONTENT_LENGTH)) -gt 0 ]; then
			log 5 "Reading $CONTENT_LENGTH more chars as request body."
			export REQUEST_BODY=$(dd count=$(($CONTENT_LENGTH)) bs=1 skip=1 2>/dev/null | tee -a scgi_input.txt)
			#echo "Request body: $REQUEST_BODY"
		fi
		
		# Closes stdin for reading (which also closes stdin for writing and clears stdin).
		#exec 0<&-
		#echo "Done reading scgi input, closed stdin."
	} 2>&1 >&103 #>&2
	
	#echo "SCGI Headers: $scgi_headers" >&2
	
	# Outputs scgi env and local env to call_daemon_with_fifo.
	{
		printf '%s\n' "$scgi_headers"
		export -p
	} | call_daemon_with_fifo
	
	log 5 "End handle_scgi"
}

# Filters input for only single-quoted safely eval'able var definitions,
# then evals each of those lines.
# Expects input as $1
eval_input_env() {
	{
		evalable_input=$(evalable_env_from_input "$1")
		set -a
		eval "$evalable_input"
		set +a
		# { echo "Evald env:"; export -p; }
	} 2>&1 >&103 #>&2
}

# Returns evalable env code from stdin.
# Expects input string on $1.
evalable_env_from_input() {
	echo "$1" | sed -ne "/^\(export \)\?[[:alnum:]_ ]\+='/,/[^']*'$/p"
}

# Evals env returned from simple haserl call.
eval_haserl_env() {
	{
		log 5 "Evaling env with haserl."
		#echo "Sending REQUEST_BODY to haserl:" >&2
		#echo "$REQUEST_BODY" >&2
		haserl_env=$(printf '%s' "$REQUEST_BODY" | haserl "$HASERL_ENV")
		#echo "Haserl env: $haserl_env" >&2
		set -a
		eval "$haserl_env"
		set +a
	} >&2
}

# Passes stdin (env list) to daemon via fifo,
# Receives response via private fifo.
call_daemon_with_fifo() {
	{
		local fifo_output="${FIFO_OUTPUT}_$$"
		cat -
		printf '%s\n' "export FIFO_OUTPUT='$fifo_output'"
		mkfifo "$fifo_output" >&2
	} >"$FIFO_INPUT"
	
	# Receive and cleanup fifo-output.
	cat "$fifo_output" &&
	rm -f "$fifo_output" >&2
}

start() {
	main_server $1
}

stop() {
	kill -15 -"$(cat $SOCAT_SERVER_PID)"
}

handle() {
	handle_$1
}

# Handles runtime/startup command processing
case $1 in
	"start")
		start $2
		;;
	"stop")
		stop $2
		;;
	"handle")
		handle $2
		;;
esac


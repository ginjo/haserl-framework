# Sets up logging.
#
# See this for log levels:
#   https://stackoverflow.com/questions/2031163/when-to-use-the-different-log-levels
#
# Usage:
#
#   Only runs logging commands when level is sufficient:
#     log <level> 'command(s)'
#
#   Redirects output to log() function of corresponding level:
#     { <program-commands>; } >&101 (for level 1)
#
#
export LOG_NAME=${LOG_NAME:=HF}
export LOG_LEVEL=${LOG_LEVEL:=3}
export LOG_LEVELS='1 2 3 4 5 6'
export LOG_NAMES='fatal error warn info debug trace'
	
log() {
	#echo "$@" >&2 ; return $?
	local level=${1:-1}
	#cmd="${@:2}"
	local cmd="${2##[^-]*}"
	#echo "log cmd: $cmd" >&2
	local str="${2##[-]*}"
	#echo "log str: $str" >&2
	{ 
		if [ $1 -le $LOG_LEVEL ]; then
			printf '%s : ' "$(date -Iseconds)$([ $LOG_LEVEL -gt 4 ] && timer ' ') $LOG_NAME ($level)"
			if [ ! -z "$cmd" ]; then
				eval "${cmd/-/}"
			elif [ ! -z "$str" ]; then
				echo "$str"
			else
				cat -
			fi
		fi
	} >&2
}

timer() {
	read up rest </proc/uptime; printf '%s' "$1$up"
}

cleanup_logging() {
	for x in $LOG_LEVELS ; do
		eval "exec 10$x>&-"
		rm -f /tmp/log_10$x
	done
	export LOGGING_IS_SETUP=
}

if [ -z "$LOGGING_IS_SETUP" ]; then
	
	for x in $LOG_LEVELS; do
		rm -f /tmp/log_10$x
		mkfifo /tmp/log_10$x
		eval "exec 10$x>&-"
		if [ $x -le $LOG_LEVEL ]; then
			eval "exec 10$x<>/tmp/log_10$x"
			#eval "{ while read -r line <&10$x; do echo \"\$line\" | log $x; done; } &"
			#eval "{ while :; do cat <&10$x | log $x; done; } &"
			while :; do
				local input="$(cat <&10$x)"
				echo "$input" | log $x
			done &
		else
			eval "exec 10$x>/dev/null"
		fi
	done

	export LOGGING_IS_SETUP=true
	
	echo "Logging activated" | log 4
	
fi
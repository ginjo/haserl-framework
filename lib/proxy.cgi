#!/usr/bin/haserl
<%# export -p | /usr/bin/nc localhost 1500 %>
<%# env > /root/cgi_dump.sh %>
<% export -p > /tmp/haserl_framework_input && cat /tmp/haserl_framework_output %>
<%# export -p | socat tcp:localhost:1500 - %>
<%#
  # Use haserl to get param parsing, as above, or...
  # use regular shell to skip param parsing but eliminate a subshell.
  #
  #!/bin/sh
  { echo "REQUEST_BODY=$(cat -)"; env; } > /tmp/haserl_framework_input && cat /tmp/haserl_framework_output
%>
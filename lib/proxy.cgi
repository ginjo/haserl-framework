#!/usr/bin/haserl
<% env > /tmp/haserl_framework_input && cat /tmp/haserl_framework_output %>
<%# env > /tmp/haserl.socket # doesn't work %>
<%#
  # Use haserl to get param parsing, as above, or...
  # Use regular shell to skip param parsing but save a fork.
  #!/bin/sh
  { echo "REQUEST_BODY=$(cat -)"; env; } > /tmp/in && cat /tmp/out
%>
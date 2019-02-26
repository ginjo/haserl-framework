#!/bin/sh
export REQUEST_BODY="$(cat -)"; export -p | socat tcp:localhost:1500 -
#!/usr/bin/haserl
# <%# export -p > /tmp/fifo_input && cat /tmp/fifo_output %>
# <%# export -p | /usr/bin/nc localhost 1500 %>
# <%# export -p | socat tcp:localhost:1500 - %>
# <%#
#   #!/bin/sh
#   export REQUEST_BODY="$(cat -)"; export -p socat tcp:localhost:1500 -
# %>

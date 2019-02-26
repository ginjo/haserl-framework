#/bin/sh

# This script handles loading of the framework into the user app.
# Paste this line into your app, after you source your env vars:
#   eval $(path-to-this-executable-file).

export HF_DIRNAME=$(dirname "$0")
#echo "export HF_DIRNAME='$HF_DIRNAME';" >&2
echo "export HF_DIRNAME='$HF_DIRNAME';"
#echo ". '$HF_DIRNAME/framework.sh'" >&2
#echo ". '$HF_DIRNAME/server.sh'" >&2
echo ". '$HF_DIRNAME/framework.sh';"
echo ". '$HF_DIRNAME/server.sh';"

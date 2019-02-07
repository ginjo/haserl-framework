# Haserl Framework

The Haserl Framework is a set of shell functions that allow one to build
MVC-style web frameworks based on cgi, shell scripts, and haserl templating.
It is similar to Ruby's Sinatra framework in structure, functionality, and spirit.

Haserl Framework is developed primarily for embedded systems running minimal *nix
distributions with limited space and shell functionality. The framework has minimal
functionality itself but can be extended infinitely at the developer's discretion.

### Flow

* A user makes a request to a cgi script on an embedded platform.
* The cgi script runs as ```#!/usr/bin/haserl``` (or wherever haserl is installed).
* The haserl script sends the environment to a FIFO file created by the framework.
* The FIFO input file is read by the framework daemon.
* The framework daemon processes the request and returns the entire response to a
  FIFO output file.
* The FIFO output file is read by the haserl-cgi script, and the response is passed
  back to the cgi interpreter.

### Dependencies
* haserl
* gpg (for encryption)
* base64 (for header and URI encoding)

### Installation

### Usage

Create an app directory with the following structure.

```text
  my_app_dir/
    |
     --app.sh
     --views/
       |
       --layout
       --home
```

In the 'app.sh' file (or whatever you want to name it), add the following shell code:

```shell
  source <path-to-this-script-file> <path-to-this-script-file>

  route '/matching/route' <optional-request-method> <<- !!
    render <view-file> <optional-layout-file>
  !!

  server
```

See the haserl man page for templating syntax.

Ash can't export functions, but some other shells can.
If you're using a shell that can export functions,
you don't need to source the helpers in your views.


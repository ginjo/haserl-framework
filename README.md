# Haserl Framework

The Haserl Framework is a set of shell functions that allow one to build
MVC-style web frameworks based on cgi, shell scripts, and haserl templating.
It is similar to Ruby's Sinatra framework in structure, functionality, and spirit.

Haserl Framework is developed primarily for embedded systems running minimal *nix
distributions with limited space and shell functionality. The framework itself has
minimal functionality but can be extended infinitely at the developer's discretion.

## Flow

* A user makes a request to a cgi script on an embedded platform.
* The cgi script runs as ```#!/usr/bin/haserl``` (or wherever haserl is installed).
* The haserl script sends the environment to a FIFO file created by the framework.
* The FIFO input file is read by the framework daemon.
* The framework daemon processes the request and returns the entire response to a
  FIFO output file.
* The FIFO output file is read by the haserl-cgi script, and the response is passed
  back to the cgi interpreter.


## Dependencies
* haserl
* gpg
* base64
* A web server with CGI support


## Installation

Clone the haserl-framework library with Git

    https://github.com/ginjo/haserl-framework.git


## Basic Setup

Create an app directory with the following structure:

```text
  my_app_dir/
   |-- app.sh
   |-- views/
        |-- layout
        |-- home
```

In the ```app.sh``` file (or whatever you want to name it), add the following shell code:
```shell
  # app.sh
  
  source <path-to-haserl-framework.sh> <path-to-haserl-framework.sh>

  route '/home' <optional-request-method> <<- !!
    # render <view-file> <optional-layout-file>
    render home.html layout.html
  !!

  server
```
Note the ```route``` and ```render``` functions. They are part of a simple DSL that
is the core UI of the framework. More on that below.


In the views directory, create a view file and populate it with haserl template code:
```haserl
    <!-- views/home.html -->
    
    <h3>Linux Release</h3>
    <pre>
      <% cat /etc/*release %>
    </pre>
```

Optionally create a layout file in the views directory:
```haserl
    <!-- views/home.html -->

    <% source path-to-haserl-framework.sh %>
    
    <html>
    <body>
      <div>
        <% yield %>
      </div>
    </body>
    </html>
```

See the haserl man page for templating syntax.

Some shells can't export functions, but others can.
If you're using a shell that can export functions,
you don't need to source the framework functions in your views.

Finally, symlink the haserl-framework proxy.cgi file to your cgi directory
(or to wherever your web server recognizes cgi programs). Make sure to
set the executable bit of this file, if it is not already.

```shell
  ln -s /usr/local/haserl-framework/proxy.cgi /var/www/cgi-bin/
```

Or create your own .cgi file and insert the following code:

```haserl
  #!/usr/bin/haserl
  <% env > /tmp/haserl_framework_input && cat /tmp/haserl_framework_output %>
```

Adjust the file paths and bang line to suit your installation.

Start the server:
```shell
  sh app.sh
  
  # or 
  
  ./app.sh  # if executable
```

Make a request in your browser.
Adjust the URL to suit your http server and CGI implementation.
```
  http://localhost/cgi-bin/proxy.cgi/home
```


## Settings & Configuration

There are a number of settings that can be customized with environment variables.
To be safe, it is recommended to store these settings in a separate file that is
not checked into your source repository. Then source the settings file
in your app.sh file _before_ sourcing haserl-framework.sh.

| Name          | Description                               | Default                 |
| ---           | ---                                       | ---                     |
| SECRET        | secret key string for cookie encryption   | \<calculated\>          |
| FIFO_INPUT    | path and name of fifo input file          | haserl_framework_input  |
| FIFO_OUTPUT   | path and name of fifo output file         | haserl_framework_output |
| APPDIR        | path to app directory                     | \<calculated\>          |


## Usage

### Routes...

### Rendering...

### Redirecting...

### Views...

### Layouts...

### Helpers...


# Haserl Framework

The Haserl Framework is a set of shell scripts and functions that allow one to build
MVC-style web applications based on shell scripting and haserl templating.
It is similar to Ruby's Sinatra framework in structure, functionality, and spirit.

Haserl Framework is developed primarily for embedded systems running minimal Linix
distributions with limited space and shell functionality. The framework itself is
relatively bare-bones but can easily be extended.

Effort has be made to keep the framework as POSIX compliant as possible, but that
is an ongoing pursuit. The original development platform for Haserl Framework
was OpenWRT's Ash/Busybox shell.

## Flow and Architecture

* A web application written with the framework's shell-based DSL
  is run as a daemon.
  
* The web server sends requests to the daemon using one of two methods.

  * Requests are passed to and from the web server, via scgi request, to a socket
    or tcp listener managed by the framework daemon.
  
  * Requests are passed (and responses received) through a pair of FIFO
    files managed by the framework daemon.
   
* Subshells wrap each request process to prevent undesirable modification
  of the daemon environment.
  
* During request processing, Haserl env variables are accessible in both
  the 'action' and the 'views'.
  
* Views, including layouts and partials, are rendered with Haserl.


## Dependencies

* haserl
* socat
* gpg
* base64
* A web server with CGI or SCGI support.

*```gpg``` and ```base64``` are only required if you want secure cookies (recommended).*

*```socat``` is not required if your app runs on a single system under CGI only.*


## Installation

Clone the haserl-framework library with Git.

    cd /usr/local/

    git clone https://github.com/ginjo/haserl-framework.git

Install dependencies. Example for OpenWRT/Busybox:

    opkg update
    
    opkg install coreutils-base64 gnupg haserl socat


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
  
  eval $(<path-to-haserl-framework/lib/load.sh>)

  route '/home' <optional-request-method> <<- !!
    # render <view-file> <optional-layout-file>
    render home.html layout.html
  !!

  start scgi  # <scgi|cgi|http>
```
Note the ```route``` and ```render``` functions. They are part of a simple DSL that
is the core UI of the framework. More on that below.


In the views directory, create a view file and populate it with haserl template code:
```haserl
    <!-- views/home.html -->
    
    <% . $HF_FRAMEWORK %>
    
    <h3>Linux Release</h3>
    <pre>
      <% cat /etc/*release %>
    </pre>
```

Optionally create a layout file in the views directory:
```haserl
    <!-- views/home.html -->

    <% . $HF_FRAMEWORK %>
    
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

If you are using a web server with SCGI reverse-proxy capabilities,
point the scgi-proxy-pass directive to the backend URL.
Here's an NGINX example:

```nginx
  # nginx.conf
  
  location /my_app {
    include   scgi_params;
    scgi_pass localhost:1500;
  }
```

*See NGINX's default scgi_params for a good default set of pass-through variables to include.*

In addition to the usual NGINX pass-through variables, here are some additional settings
to get path-info, script-name, and request-scheme variables passed to your application:

```nginx
  # nginx.conf
  
  # Path-info and script-name must be calculated by nginx.
  # Note the use of fastcgi functions. These work even though we're using scgi.
  #
  fastcgi_split_path_info        ^(/scgi)(/.+)$;
  scgi_param  PATH_INFO          $fastcgi_path_info;
  scgi_param  SCRIPT_NAME        $fastcgi_script_name;

  # Request-scheme may not be included in the nginx default scgi_params file.
  scgi_param  REQUEST_SCHEME     $scheme;
```

If you are using CGI, create a CGI script and insert the following code.
Remember to adjust the file paths and shebang line to suit your installation.
You can name the file anything. In this example ```proxy.cgi``` is a descriptive name,
since the cgi script is simply passing data to the framework daemon.

```haserl
  #!/usr/sh
  <% export -p > /tmp/fifo_input && cat /tmp/fifo_output %>
```

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
| FIFO_INPUT    | path and name of fifo input file          | fifo_input              |
| FIFO_OUTPUT   | path and name of fifo output file         | fifo_output             |
| APPDIR        | path to app directory                     | \<calculated\>          |
| LOG_LEVEL     | 1 through 6 (FATAL through TRACE)         | 4 (INFO)                |


## Usage

### Routes...

### Rendering...

### Redirecting...

### Views...

### Layouts...

### Server...

### Helpers...

### Security...


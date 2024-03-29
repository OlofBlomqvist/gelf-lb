# GELF-LB

A simple to use UDP round-robin load-balancer for GELF packets (graylog messages).

# Why

Normally you would not be able to properly do round-robin loadblancing for GELF over UDP properly while using chunked packets as different chunks would end up on different servers, causing the messages to be discarded. This custom implementation will inspect each packet before forwarding, ensuring that all chunks for a specific message id go to the same backend.

# Linux

In order to build on ubuntu you need to install gcc & gcc-multilib
```bash
sudo apt-get install -y gcc gcc-multilib
```

# Windows

It is possible to build & run this application also on Windows clients such as Windows 11 but it will then not act as a transparent proxy: the source of all log messages will seem to come from the loadbalancer. If you want to run this LB in such environments, you might want to use the "attach_source_info" setting to extend all logged messages with the original source ip and dns names.

# How to install

There is no installer, just a binary. If you do not wish to build it yourself you can download the latest release from the github repository.

# How to run

Example configuration file:
```toml
listen_ip = "0.0.0.0" # defaults to 127.0.0.1. can also use ipv6 here like this: "[::1]" 
listen_port = 12201
web_ui_port = 8080 # optional , remove to disable
chunk_size = 1024 # used only if you use settings that modify messages such as: attach_source_info,strip_fields or blank_fields
use_gzip = true # defaults to true. used only if you use settings that modify messages such as: attach_source_info,strip_fields or blank_fields.
strip_fields = [ # drop any given field from all messages prior to forwarding them.
    "password", 
    "secret"
]
blank_fields = [ # sets string fields to "******" before forwarding
    "PID"
]
log_level = "info" # (defaults to RUST_LOG env var if it exists, otherwise 'info') trace/debug/info/warn/error
transparent = true # (default:true) keep the original source IP addr when forwarding - this is not allowed on non-server versions of Windows
attach_source_info = false # (default: false) attach the original source IP and DNS name fields to all logged messages - mostly useful when running on non-server versions of Windows
allowed_source_ips = [ # defaults to an empty array. use this if you wish to only allow forwarding from specific sources
    "192.168.1.122"
]
backends = [
    { ip = "192.168.1.22", port = 12201 },
    { ip = "192.168.1.44", port = 12201 },    
]
```

Run with:
```bash
./gelflb ./path/to/your_file.toml
```

If you do not provide a path, gelflb will default to looking for "./gelflb.toml" in the current directory.


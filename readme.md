# GELFLB

A simple to use UDP round-robin load-balancer for GELF packets (graylog messages).

# Why

Normally you would not be able to properly do round-robin loadblancing for GELF over UDP properly while using chunked packets as different chunks would end up on different servers, causing the messages to be discarded. This custom implementation will inspect each packet before forwarding, ensuring that all chunks for a specific message id go to the same backend.

# Linux specific information

In order to build on Linux you need to install gcc and gcc-multilib:
```bash
sudo apt-get install gcc gcc-multilib
```

# Windows specific information

It is possible to build & run this application also on Windows clients such as Windows 11 but it will then not act as a transparent proxy: the source of all log messages will seem to come from the loadbalancer. If you want to run this LB in such environments, you might want to use the "attach_source_info" setting to extend all logged messages with the original source ip and dns names.

# How to install

If you do not wish to build the application yourself you can download the latest release from the github repository or use Cargo to install from Crates.io.

# How to run

Example configuration file:
```toml
listen_ip = "0.0.0.0" # defaults to 127.0.0.1. can also use ipv6 here like this: "[::1]" 
listen_port = 12201
strip_fields = [ # drop any given field from all messages prior to forwarding them.
    "password", 
    "secret"
]
blank_fields = [ # sets string fields to "******" before forwarding
    "PID"
]
log_level = info # (default:info) trace/debug/info/warn/errt
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


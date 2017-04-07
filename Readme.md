# PAM Riemann client

## Introduction
[Riemann](http://riemann.io/) is a tool for data ingestion and processing. It is primarily devoted to network events, but it's heart, Clojure, makes it possible to use it also within other domains. Ons of them is *network security*. My contribution is a Linux PAM module, acting as a "silent" Riemann client. It detects any auth attempt and send the relative event to a Riemann configured server for data collection.

## Dependencies

The present code relies on the following packages:

* [riemann-c-client](https://github.com/algernon/riemann-c-client) by Gergely Nagy
* libpam0g-dev PAM development


## Build and Install

Download and extract the repo, then:
```
$ cd pam-riemann/Debug
$ make
```

Then assuming the PAM modules are in `/lib/x86_64/security/` copy the shared obiect as
```
$ sudo cp libpam-riemann.so /lib/x86_64/security/pam-riemann.so
$ sudo chown 644 /lib/x86_64/security/pam-riemann.so
```

## Usage

To enable the module add it as `requisite` in the auth section of a PAM application. As an example in the `/etc/pam.d/sshd` file add on top the following line to configuration:
```
auth    required        pam_riemann.so server=10.11.12.13 port=5555
```
where *10.11.12.13* is the IP address of the configured Riemann server.

## Credits
pam-riemann is a creation of [Luca Simone Ronga](https://github.com/rongals) (c) 2017

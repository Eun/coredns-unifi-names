# unifi-names

*unifi-names* is an [coredns](https://github.com/coredns/coredns/) plugin, it resolves custom set names to the corresponding
client ip.


## Syntax
```
unifi-names {
    # map the Unifi network "LAN" to example1.com
    # this means that a client that is in the "LAN" network will be suffixed with this value, e.g. mikes-notebook.lan.local
    Network LAN lan.local

    # You can map multiple networks here
    Network VLAN1 vlan1.local
    Network VLAN2 vlan1.local

    # Setup the unifi controler
    # the syntax is
    #   Unifi https://url-to-controller/ site-name username password ssl-certificate-fingerprint
    #
    #   site-name: is most of the time "default"
    #   username: username to use for login
    #   password: password to use for login
    #   ssl-certificate-fingerprint: an sha1 hash to verify the ssl certifacte with
    #    (if skipped the normal verification process will be used, usefull for self signed certificates) 
    # example:
    Unifi https://localhost:8443/ default admin secret1234 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
    # standart ttl to use (this is also the refresh rate of getting the clients)
    TTL 3600
    # enable debug log output
    Debug
}
```
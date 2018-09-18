##! This script identifies and sends DNS servers to the environment
##! framework for documentation

module Environment;

export {

    ## DNS_SERVER is any device seen responding to DNS queries
    redef enum Environment::HostType += { DNS_SERVER };

    ## DNS_SERVERS holds identified DNS servers for the Environment
    ## module to be aware of
    option DNS_SERVERS: set[addr] = {};

    ## Local cache of DNS servers to prevent massive amounts of calls to
    ## add_to_environment. 
    global seen_dns_servers: set[addr] &create_expire=60min;
}

event connection_state_remove(c: connection)
    {
    if ( "DNS" in c$service && c$id$resp_h !in seen_dns_servers 
            && c$history == "SF"
            && addr_matches_host(c$id$resp_h, host_tracking) && c$id$resp_p != 137/udp )
        {
        local documented = F;
        if ( c$id$resp_h in DNS_SERVERS )
            documented = T;

        Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                                $uid = c$uid,
                                                $host = c$id$resp_h,
                                                $host_type = DNS_SERVER,
                                                $documented = documented));

        add seen_dns_servers[c$id$resp_h];
        }
    }
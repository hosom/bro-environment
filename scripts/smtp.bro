##! This script helps to identify SMTP servers in the environment.

module Environment;

export {
    ## SMTP_SERVER is any device seen accepting SMTP
    redef enum Environment::HostType += { SMTP_SERVER };

    ## SMTP_SERVERS holds identified SMTP servers for the environment
    option SMTP_SERVERS: set[addr] = {};

    ## Local cache of smtp servers to prevent obnoxious amounts of calls
    ## to the add_to_environment function
    global seen_smtp_servers: set[addr] &create_expire=60min;
}

event connection_state_remove(c: connection)
    {
    if ( "SMTP" in c$service && c$id$resp_h !in seen_smtp_servers && addr_matches_host(c$id$resp_h, host_tracking) )
        {
        local documented = F;
        if ( c$id$resp_h in SMTP_SERVERS )
            documented = T;
        
        Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                                    $uid = c$uid,
                                                    $host = c$id$resp_h,
                                                    $host_type = SMTP_SERVER,
                                                    $documented = documented));
        
        add seen_smtp_servers[c$id$resp_h];
        }
    }
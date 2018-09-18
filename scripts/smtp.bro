##! This script helps to identify SMTP servers in the environment.

module Environment;

export {
    ## SMTP_SERVER is any device seen accepting SMTP
    redef enum Environment::HostType += { SMTP_SERVER };

    ## SMTP_SERVERS holds identified SMTP servers for the environment
    option SMTP_SERVERS: set[addr] = {};
}

event connection_state_remove(c: connection)
    {
    if ( "SMTP" in c$service )
        {
        local documented = F;
        if ( c$id$resp_h in SMTP_SERVERS )
            documented = T;
        
        Environment::add_to_environment(HostsInfo($ts = c$ts,
                                                    $uid = c$uid,
                                                    $host = c$id$resp_h,
                                                    $host_type = SMTP_SERVER,
                                                    $documented = documented));
        }
    }
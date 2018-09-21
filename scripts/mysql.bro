##! This script identifies and sends mysql servers to the environment
##! framework for documentation

module Environment;

export {
    ## MYSQL_SERVER is any device that is seen running MySQL
    redef enum Environment::HostType += { MYSQL_SERVER };

    ## MYSQL_SERVERS holds identified MySQL servers for the Environment
    ## module to be aware of
    option MYSQL_SERVERS: set[addr] = {};

    ## Local cache of mysql servers to prevent a large number of calls
    ## from being made to add_to_environment.
    global seen_mysql_servers: set[addr] &create_expire=60min;
}

event mysql_server_version(c: connection, ver: string)
    {
    if ( c$id$resp_h !in seen_mysql_servers 
        && addr_matches_host(c$id$resp_h, host_tracking) )
        {
        local documented = F;

        if ( c$id$resp_h in MYSQL_SERVERS )
            documented = T;
        
        Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                                $uid = c$uid,
                                                $host = c$id$resp_h,
                                                $host_type = MYSQL_SERVER,
                                                $documented = documented));

        add seen_mysql_servers[c$id$resp_h];
        }
    }
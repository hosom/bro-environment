##! This script identifies and sends AD domain controllers to the environment
##! framework for documentation

module Environment;

export {
    ## DOMAIN_CONTROLLER is any device seen acting as an AD domain controller
    redef enum Environment::HostType += { DOMAIN_CONTROLLER };

    ## DOMAIN_CONTROLLERS holds identified domain controllers for the 
    ## Environment framework to be aware of
    option DOMAIN_CONTROLLERS: set[addr] = {};

    ## seen_domain_controllers is used to prevent a large number of calls to
    ## add_to_environment
    global seen_domain_controllers: set[addr] &create_expire=60min;
}

event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse)
    {
    if ( /\\sysvol$/ in c$smb_state$current_tree$path
        && c$id$resp_h !in seen_domain_controllers
        && addr_matches_host(c$id$resp_h, host_tracking))
        {
        local documented = F;

        if ( c$id$resp_h in DOMAIN_CONTROLLERS )
            documented = T;
        
        Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                        $uid = c$uid,
                                        $host = c$id$resp_h,
                                        $host_type=DOMAIN_CONTROLLER,
                                        $documented = documented));

        add seen_domain_controllers[c$id$resp_h];
        }
    }


event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string)
    {
    if ( /\\sysvol$/ in c$smb_state$current_tree$path
        && c$id$resp_h !in seen_domain_controllers
        && addr_matches_host(c$id$resp_h, host_tracking))
        {
        local documented = F;

        if ( c$id$resp_h in DOMAIN_CONTROLLERS )
            documented = T;
        
        Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                        $uid = c$uid,
                                        $host = c$id$resp_h,
                                        $host_type=DOMAIN_CONTROLLER,
                                        $documented = documented));

        add seen_domain_controllers[c$id$resp_h];
        }
    }
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

# drsuapi is the rpc endpoint used for domain replication. In any environment
# with >1 domain controllers, this endpoint will be heavily used. With this 
# method, we can detect DCs that aren't client facing.
event dce_rpc_response(c: connection, fid: count, ctx_id: count, 
    opnum: count, stub_len: count)
    {
    if ( c?$dce_rpc && c$dce_rpc?$endpoint && c$dce_rpc?$operation )
        {
        if ( c$dce_rpc$endpoint == "drsuapi" 
            && c$id$resp_h !in seen_domain_controllers 
            && addr_matches_host(c$id$resp_h, host_tracking) )
            {
            local documented = F;

            if ( c$id$resp_h in DOMAIN_CONTROLLERS )
                documented = T;
            
            Environment::add_to_environment(HostsInfo($ts = c$start_time,
                                            $uid = c$uid,
                                            $host = c$id$resp_h,
                                            $host_type = DOMAIN_CONTROLLER,
                                            $documented = documented));

            add seen_domain_controllers[c$id$resp_h];
            }
        }
    }

# sysvol shares public files from a domain controller. This should be a solid
# way to detect client facing domain controllers. This is also reliable for 
# detecting domain controllers in domains with only a single domain controller
event smb2_tree_connect_response(c: connection, hdr: SMB2::Header, response: SMB2::TreeConnectResponse)
    {
    if ( ! c?$smb_state && c$smb_state?$current_tree && c$smb_state$current_tree?$path )
        return;

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

# implement sysvol detection for smb1 systems *just in case*
event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string)
    {
    if ( ! c?$smb_state && c$smb_state?$current_tree && c$smb_state$current_tree?$path )
        return;
    
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
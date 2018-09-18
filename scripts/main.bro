##! This script is intended to be used to help identify and document services
##! within an environment. 

module Environment;

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

## Define configuration file for options for the Environment module
redef Config::config_files += { fmt("%s/environment.dat", @DIR) };

export {
    ## The environment logging stream identifier.
    redef enum Log::ID += { ENVIRONMENT_LOG };

    ## The enum that identifies the type of host that was detected.
    type HostType: enum {
        ## Base server type to initialize the Enum, this value is not 
        ## intended to be used and you should use a more specific value
        ## of your own.
        GENERIC_SERVER
    };

    ## The record type that contains the column fields for environment.log
    type HostsInfo: record {
        ## The timestamp at which the host was detected
        ts: time &log;
        ## The connection ID of the connection used to identify the service.
        uid: string &log;
        ## The address that was detected originating or responding for
        ## a documented service.
        host: addr &log;
        ## The type of service that the host has been seen hosting.
        host_type: HostType &log;
        ## Whether or not the device is acknowledged as known.
        documented: bool &log;
    };

    ## Holds the set of all known environment services.
    global environment_store: Cluster::StoreInfo;

    ## The broker topic name to use for environment_store
    const environment_store_name = "bro/environment";

    ## The expiry interval of new entries 
    ## By default, new entries do not expire
    const environment_store_expiry = 1day &redef;

    ## The hosts that should be tracked by default
    ## note: you probably shouldn't change this value unless you REALLY
    ## know what you are doing.
    option host_tracking = LOCAL_HOSTS;

    ## The timeout for how long Broker operations should take.
    option environment_store_timeout = 15sec;

    ## Persist environment state through a restart
    option persist = F;

    ## add_to_environment allows accompanying scripts to add a host to 
    ## the environment tracking store.
    global add_to_environment: function(h: HostsInfo);

    ## discovery is an event used to allow scripts to use the environment
    ## information before it is sent to the logging framework.
    ## note: this event only occurs on the node where the discovery was made
    global discovery: event(h: HostsInfo);

    ## An event that can be handled to access the HostsInfo 
    ## record on its way to the logging framework.
    global log_environment: event(rec: HostsInfo);
}

event bro_init()
    {
    # initialize the Broker store
    Environment::environment_store = Cluster::create_store(
        Environment::environment_store_name, persist);
    }

event bro_init()
    {
    # create logging stream
    Log::create_stream(Environment::ENVIRONMENT_LOG,
        [$columns=HostsInfo, $ev=log_environment, $path="environment"]);
    }

event Environment::discovery(h: HostsInfo) &priority=-10
    {
    # write the environment record to environment log
    Log::write(Environment::ENVIRONMENT_LOG, h);
    }

function add_to_environment(h: HostsInfo)
    {
    # Don't handle hosts that aren't in host_tracking
    if ( !addr_matches_host(h$host, host_tracking) )
        return;

    # Add the environment record to the environment store.
    when ( local r = Broker::put_unique(Environment::environment_store$store,
                                        fmt("%s%s", h$host, h$host_type),
                                        h$documented,
                                        environment_store_expiry))
    {
        if ( r$status == Broker::SUCCESS )
            {
            if ( r$result as bool )
                event Environment::discovery(h);
            }
        else 
            {
            Reporter::error("Failed put_unique to Environment store.");
            event Environment::discovery(h);
            }
    }
    timeout Environment::environment_store_timeout
        {
        Reporter::error("Timeout on put_unique to Environment store.");
        event Environment::discovery(h);
        }
    }
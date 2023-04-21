# IDN2NewRelic

Send audit logs from SailPoint IDN to New Relic 

## High Level workflow:
* Periodically query the IDN Search API to retrieve  the latest event logs
* Forward the events to New Relic using the New Relic logging API 
* Map events of custom log source so we can build rules triggering on certain event conditions




### Considerations:
* The search API allows querying events with filters e.g.  `created:>2021-02-28` but log events in the IDN API can become available with a slight delay. We have to build a mechanism that  queries  the latest events allowing for them to be delayed: `created:>{query_checkpoint_time} AND created:<{current_time - query_search_delay}`
* As seen above we need to record a checkpoint time that contains the last event that was retrieved from the API so we have a starting point for the next execution run. We store this value in  Azure App Configuration to keep state between executions.
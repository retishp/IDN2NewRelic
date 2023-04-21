# encoding = utf-8

import os
import sys
import time
import datetime
import requests
from requests.exceptions import HTTPError
import json
import re
from builtins import object
import logging
import logging.handlers
import configparser
from azure.appconfiguration import AzureAppConfigurationClient, ConfigurationSetting


class Helper(object):
    def __init__(self, logger=None):
        self.logger = logger
        self.http_session = None
        self.requests_proxy = None


    def log_error(self, msg):
        print(msg)
        if self.logger:
            self.logger.error(msg)

    def log_info(self, msg):
        print(msg)
        if self.logger:
            self.logger.info(msg)

    def log_debug(self, msg):
        print(msg)
        if self.__logger:
            self.__logger.debug(msg)

    def _init_request_session(self, proxy_uri=None):
        self.http_session = requests.Session()
        self.http_session.mount(
            'http://', requests.adapters.HTTPAdapter(max_retries=3))
        self.http_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=3))
        if proxy_uri:
            self.requests_proxy = {'http': proxy_uri, 'https': proxy_uri}

    def send_http_request(self, url, method, parameters=None, payload=None, headers=None, cookies=None, verify=True,
                          cert=None, timeout=None, proxy_uri=None, use_proxy=False):
        if self.http_session is None:
            self._init_request_session(proxy_uri)
        # connect and read timeouts in tuple
        requests_args = {'timeout': (5.0, 25.0), 'verify': verify}
        if parameters:
            requests_args['params'] = parameters
        if payload:
            if isinstance(payload, (dict, list)):
                requests_args['json'] = payload
            else:
                requests_args['data'] = str(payload)
        if headers:
            requests_args['headers'] = headers
        if cookies:
            requests_args['cookies'] = cookies
        if cert:
            requests_args['cert'] = cert
        if timeout is not None:
            requests_args['timeout'] = timeout
            
        if self.requests_proxy:
            requests_args['proxies'] = self.requests_proxy

        req = self.http_session.request(method, url, **requests_args)
        return req

#This method will determine if the current timestamp should be used instead of the value stored in the checkpoint file. Will return 'true' if the checkpoint time is 1 or more days in the past

def use_current(now, old):
    ret = False
    
    try:
        a = datetime.datetime.strptime(now, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        a = datetime.datetime.strptime(now, '%Y-%m-%dT%H:%M:%SZ')
        
    try:
        b = datetime.datetime.strptime(old, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        b = datetime.datetime.strptime(old, '%Y-%m-%dT%H:%M:%SZ')
        
    diff = a - b
    delta_days = diff.days
    
    if(int(delta_days) > 0):
        ret = True
        
    return ret

def collect_events(helper):
    
    # Get Sailpoint secure client id & secret from Azure App Config
    connection_string = os.getenv('AZURE_APPCONFIG_CONNECTION_STRING')
    app_config_client = AzureAppConfigurationClient.from_connection_string(connection_string)
   
    client_id = app_config_client.get_configuration_setting(key='sailpoint-client-id').value
    client_secret = app_config_client.get_configuration_setting(key='sailpoint-client-secret').value
    org_name = app_config_client.get_configuration_setting(key='sailpoint-tenant').value
    newrelic_url = app_config_client.get_configuration_setting(key='newrelic-url').value
    newrelic_licensekey = app_config_client.get_configuration_setting(key='newrelic_license').value
    
    
    # NR initialization
    nr_block_size = 100 # Number of events to send to NR per Post message
    nr_event_head = "[{ \"common\": { \"attributes\": { \"logtype\": \"Sailpoint\" } },  \"logs\": [ "
    nr_event_tail = " ] }]"
    nr_event_body = ""
    send_event = ""
    newrelic_headers = {'Content-Type': 'application/json','Content-Encoding': 'application/gzip', 'Api-key' : newrelic_licensekey}

    # Get information about IdentityNow from the input configuration
    # Information on how to attain these values can be found on community.sailpoint.com
    base_url = 'https://{}.api.identitynow.com'.format(org_name)
    tenant = {
        "url" : base_url, 
        "client_id" : client_id,
        "client_secret" : client_secret
    }
    
    if not tenant["url"].startswith("https"):
       helper.log_error("Requires communication over TLS/SSL, check IdentityNow API Gateway URL")
       return 0
       
    # Read the timestamp from the checkpoint variable in Azure AppConfig
    # - The checkpoint contains the ISO datetime of the 'created' field of the last event seen in the
    #   previous execution of the script. If the checkpoint time was greater than a day in the past, use current datetime to avoid massive load if search disabled for long period of time
    
   
    new_checkpoint_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=60)).isoformat() + "Z"
    #Set checkpoint time to either the current timestamp, or what was saved in the checkpoint

    checkpointConfig = app_config_client.get_configuration_setting(key='sailpoint-checkpoint')
    checkpoint = checkpointConfig.value

    if checkpoint:
        checkpoint_time = checkpoint
        if use_current(new_checkpoint_time, checkpoint_time):
            checkpoint_time = new_checkpoint_time
    else:
        checkpoint_time = new_checkpoint_time
    
    # JWT RETRIEVAL    
    # The following request is responsible for retrieving a valid JWT token from the IdentityNow tenant
    tokenparams = {
        "grant_type": "client_credentials",
        "client_id": tenant["client_id"],
        "client_secret": tenant["client_secret"]
    }
        
    token_url = tenant["url"] + "/oauth/token"

    access_token = ""
    
    token_response = helper.send_http_request(token_url, "POST", parameters=tokenparams, payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None)

    if token_response is not None:
        try:
            token_response.raise_for_status()
            
            access_token = token_response.json()["access_token"]
            headers = {
                'Content-Type' : 'application/json', 
                'Authorization' : "Bearer " + access_token
            }
        except HTTPError as http_err:
            helper.log_error("Error getting token: " + str(token_response.status_code))
            return 0
        except KeyError:
            helper.log_error("Access token not granted...")
        except ValueError:
            helper.log_error("No json response received...")

    # END GET JWT LOGIC

    partial_set = False
    count_returned = 0
    audit_events = []
    
    #Search API results are slightly delayed, allow for 5 minutes though in reality
    #this time will be much shorter. Cap query at checkpoint time to 5 minutes ago
    search_delay_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).isoformat() + "Z"


    #Number of Events to return per call to the search API
    limit = 10000
    
    while True:

        if partial_set == True:
            break
        
        #Standard query params, but include limit for result set size
        queryparams = {
            "count": "true",
            "offset": "0",
            "limit": limit
        }
        
        helper.log_error(f'checkpoint_time {checkpoint_time} search_delay_time {search_delay_time}')
        query_checkpoint_time = checkpoint_time.replace('-', '\\-').replace('.', '\\.').replace(':', '\\:')
        query_search_delay_time = search_delay_time.replace('-', '\\-').replace('.', '\\.').replace(':', '\\:')

        
        #Search criteria - retrieve all audit events since the checkpoint time, sorted by created date
        searchpayload = {
            "queryType": "SAILPOINT",
            "query": {
                "query": f"created:>{query_checkpoint_time} AND created:<{query_search_delay_time}" 
                # "query": f"created:>=2021-02-28" 
            },
            "queryResultFilter": {},
            "sort": ["created"],
            "searchAfter": []
        }
           
        audit_url = tenant["url"] + "/v3/search/events"

        #Initiate request        
        response = helper.send_http_request(audit_url, "POST", parameters=queryparams, payload=searchpayload, headers=headers, cookies=None, verify=True, cert=None, timeout=None)
        helper.log_error(f' audit url {audit_url}')
        helper.log_error(f' query params {queryparams}')
        helper.log_error(f' search payload {searchpayload}')
        helper.log_error(f' headers {headers}')


        # API Gateway saturated / rate limit encountered.  Delay and try again. Delay will either be dictated by IdentiyNow server response or 5 seconds
        if response.status_code == 429:
            
            retryDelay = 5
            retryAfter = response.headers['Retry-After']
            if retryAfter is not None:
                retryDelay = 1000 * int(retryAfter)
                
            helper.log_warning("429 - Rate Limit Exceeded, retrying in " + str(retryDelay))
            time.sleep(retryDelay)
            
        elif response.ok:    
            
            # Check response headers to get toal number of search results - if this value is 0 there is nothing to parse, if it is less than the limit value then we are caught up to most recent, and can exit the query loop
            x_total_count = int(response.headers['X-Total-Count'])
            if x_total_count > 0:
                if response.json() is not None:
                    try:
                        if x_total_count < limit:
                            #less than limit returned, caught up so exit
                            partial_set = True
    
                        results = response.json()
                        #Add this set of results to the audit events array
                        audit_events.extend(results)
                        current_last_event = audit_events[-1]
                        checkpoint_time = current_last_event['created']
                    except KeyError:
                        helper.log_error("Response does not contain items")
                        break
            else:
                #Set partial_set to True to exit loop (no results)
                partial_set = True
        else:
            helper.log_error("Failure from server" + str(response.status_code))
            #hard exit
            return 0

    #Iterate the audit events array and create events for each one
    
    if len(audit_events) > 0:
        counter = 0
        len_audit_events = len(audit_events)
        
        for audit_event_count, audit_event in enumerate(audit_events):
            counter = counter + 1
            #str_audit_event = ""
            #updated_audit_event = ""
            str_audit_event = str(audit_event)
            updated_audit_event = str_audit_event.replace('"', '\\"').replace("'","\"" )
            #updated_audit_event2 = updated_audit_event.replace("'","\"" )
            #nr_event = "{\"logtype\": \"Sailpoint\", \"message\" : " +  updated_audit_event2 + " }"
            # Add comma at the end of message json if less than post block size or not last item in array
            if (counter < nr_block_size) and (audit_event_count < len_audit_events):
                nr_event_body = nr_event_body + "{ \"message\" : " +  updated_audit_event + " } ,"                
            # If Post block size has reached or last element in array, post the array to NR
            if ((counter >= nr_block_size) or (audit_event_count == (len_audit_events - 1))):
                nr_event_body = nr_event_body + "{ \"message\" : " +  updated_audit_event + " } "
                send_event = nr_event_head + nr_event_body + nr_event_tail
                requests.post(newrelic_url, 
                send_event, headers=newrelic_headers)
                counter = 0
                nr_event_body = ""

        print("sent {} events to {}".format(len(send_event), newrelic_url))
        #Get the created date of the last AuditEvent in this run and save it as the checkpoint time AWS parameter
        last_event = audit_events[-1]
        new_checkpoint_time = last_event['created']
        checkpointConfig.value = new_checkpoint_time
        app_config_client.set_configuration_setting(checkpointConfig)
        #helper.store.set_parameter('sailpoint-checkpoint', new_checkpoint_time)
 

if __name__ == "__main__":
    helper = Helper()
    collect_events(helper)


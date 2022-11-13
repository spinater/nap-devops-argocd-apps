require 'time'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'

def register(params)
    $stdout.sync = true
end

def filter(event)
    header = event.get('headers')
    nas_src = header['nas_source']
    storage_data = event.get('StorageData')

    #puts("DEBUG - Event hooked [#{nas_src}]")

    if (nas_src == 'office-hq')
        msg = event.get('Message Content').delete!("\n")

        event.set('category', 'synology-noti')
        event.set('type', 'webhook')
        event.set('message', msg)
    elsif (!storage_data.nil?)
        event.set('category', 'gcs-ftp')
        event.set('type', 'webhook')
        event.set('message', storage_data.to_json)
    else
        event.set('category', 'unknown')
        event.set('type', 'webhook')
        event.set('message', storage_data.to_json)        
    end

    return [event]
end

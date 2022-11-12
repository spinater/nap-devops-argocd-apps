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

    puts("DEBUG - Event hooked [#{nas_src}]")

    if (nas_src == 'office-hq')
        msg = event.get('Message Content').delete!("\n")

        event.set('category', 'synology')
        event.set('type', 'notification')

        event.set('message', msg)
    end

    return [event]
end

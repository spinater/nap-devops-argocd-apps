require 'time'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'

def register(params)
    $stdout.sync = true
end

def filter(event)
    puts("DEBUG - Event hooked")

    return [event]
end

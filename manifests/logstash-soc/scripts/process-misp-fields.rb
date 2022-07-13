def register(params)
    $stdout.sync = true
end

def filter(event)    
    misp_dst_ip = event.get('misp_dst_ip')
    misp_domain = event.get('misp_domain')

    puts "#### Processing MISP data field [misp_dst_ip] value [#{misp_dst_ip}]"
    puts "#### Processing MISP data field [misp_domain] value [#{misp_domain}]\n"

    #event.set('misp_category', '')

    return [event]
end

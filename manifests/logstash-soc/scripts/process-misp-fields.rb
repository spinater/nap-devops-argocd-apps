def register(params)
    $stdout.sync = true
end

def filter(event)    
    misp_dst_ip = event.get('misp_dst_ip')
    misp_domain = event.get('misp_domain')
    dst_ip = event.get('dst_ip')
    domain = event.get('domain')

    if dst_ip != '' and !dst_ip.nil?
        puts "#### Processing MISP data field [misp_dst_ip] value [#{misp_dst_ip}]"
        #event.set('misp_category', '')
    end

    if domain != '' and !domain.nil?
        puts "#### Processing MISP data field [misp_domain] value [#{misp_domain}]\n"
        #event.set('misp_category', '')
    end

    return [event]
end

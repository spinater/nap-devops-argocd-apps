#Labels {'user', 'domain', 'src_ip', 'dst_ip', 'mac', 'src_net', 'dst_net', 'src_port', 'dst_port'}
require 'time'

def register(params)
end

def extract_hotspot(event, message, category)
    #hotspot,account,info,debug 0-Napbiotec: seubpong.mon (192.168.20.29): logged in
    groups = message.scan(/^.*:\s(.+?)\s\((.+?)\):.+$/i)[0]
    user = groups[0]
    src_ip = groups[1]

    event.set('user', user.strip)
    event.set('src_ip', src_ip.strip)
    event.set('debug_field1', category)
end

def extract_firewall(event, message, category)
    #   0                1          2            3               4           5             6           7    8        9                          10                    11                
    # firewall,info 0-Napbiotec: forward: in:vlan20-office out:pppoe-tot, src-mac b4:0f:b3:1d:63:4b, proto TCP (ACK,FIN,PSH), 192.168.20.171:43996->47.241.18.42:443, NAT (192.168.20.171:43996->125.25.69.110:43996)->47.241.18.42:443, len 71
    if message.include? "NAT"
        groups = message.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\sNAT\s(.*)$/i)[0]
    else
        groups = message.scan(/^.*?in:(.+?)\s+out:(.+?),\s*src-mac\s+(.+?),.*,\s*(.+?):(.+?)->(.+?):(.+?),\slen\s(.*)$/i)[0]
    end
    src_net = groups[0]
    dst_net = groups[1]
    mac = groups[2]
    src_ip = groups[3]
    src_port = groups[4]
    dst_ip = groups[5]
    dst_port = groups[6]

    event.set('src_net', src_net.strip)
    event.set('dst_net', dst_net.strip)
    event.set('mac', mac.strip)
    event.set('src_ip', src_ip.strip)
    event.set('src_port', src_port.strip)
    event.set('dst_ip', dst_ip.strip)
    event.set('dst_port', dst_port.strip)
    event.set('debug_field1', category)
end

def extract_webproxy(event, data, category)
    #   0         1              2        3                  4                            5
    #account 0-Napbiotec: 192.168.20.115 GET http://cu.bwc.brother.com/certset/ver  action=allow cache=MISS        
    arr2 = data.split(' ')
    src_ip = arr2[2]
    url = arr2[4]

    event.set('src_ip', src_ip.strip)
    event.set('domain', URI.parse(url).host)
    event.set('debug_field1', category)
end

def extract_dhcp(event, data, category)
    # 0        1         2      3           4         5       6   
    #info 0-Napbiotec: dhcp6 assigned 192.168.30.236 to E2:9B:9D:A9:DF:5B
    arr2 = data.split(' ')
    src_ip = arr2[4]
    mac = arr2[6]

    event.set('src_ip', src_ip.strip)
    event.set('mac', mac)
    event.set('debug_field1', category)
end

def extract_dns(event, message, category)
    #dns 0-Napbiotec: query from 170.81.19.85: #16897106 peacecorps.gov. ALL
    event.set('debug_field1', "unknown")

    if match = message.match(/^dns.+query from (.+?): .+ (.+)\..*$/i)
        src_ip, domain = match.captures

        event.set('src_ip', src_ip.strip)
        event.set('domain', domain)
        event.set('debug_field1', category)
    end
end

def get_category(message)
    category = "undefined"

    if message.include? "Omada Controller"
        category = "omda-controller"
    else
        arr1 = message.split(',')
        category = arr1[0]        
    end

    if category.length > 20
        sub_cat = category[0, 4]
        category = "unknown"

        if sub_cat == "dns " #Need a space at the end
            #dns 0-Napbiotec: done query: #16768652 dns name exists, but no appropriate record
            category = "dns"
        end
    end

    return category
end

def filter(event)
    data = event.get('message')
    arr1 = data.split(',')
    category = get_category(data)

    #current_time = event.get('@timestamp') + '' #convert to string
    #time = Time.new
    #event.set('yyyy', time.strftime("%Y"))
    #event.set('yyyymm', time.strftime("%Y%m"))
    #event.set('yyyymmdd', time.strftime("%Y%m%d"))

    event.set('type', 'syslog')
    event.set('debug_field1', 'not-matched')
    event.set('category', category)    

    if category == 'hotspot'
        extract_hotspot(event, data, category)
    elsif category == 'web-proxy'
        data1 = arr1[1]
        extract_webproxy(event, data1, category)
    elsif category == 'dhcp'
        data1 = arr1[1]
        extract_dhcp(event, data1, category)
    elsif category == 'firewall'
        extract_firewall(event, data, category)
    elsif category == 'dns'
        extract_dns(event, data, category)        
    end

    return [event]
end

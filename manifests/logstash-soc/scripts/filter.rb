#Example : https://fabianlee.org/2017/04/24/elk-using-ruby-in-logstash-filters/
#Labels {'user', 'domain', 'src_ip', 'dst_ip', 'mac', 'src_net', 'dst_net', 'src_port', 'dst_port'}

def register(params)
end

def filter(event)
    arr1 = event.get('message').split(',')
    category = arr1[0]
    event.set('debug_field1', 'not-matched')

    if category == 'hotspot'
        data1 = arr1[2]
        #debug 0-Napbiotec: chandet.pun@napbiotec.io (192.168.20.171): logged out: lost dhcp lease
        arr2 = data1.split(':')
        data2 = arr2[1] #chandet.pun@napbiotec.io (192.168.20.171)

        dat = data2.scan(/^\s*(.*?)\s*(\(.+\))$/i)[0]
        user = dat[0]
        src_ip = dat[1]

        event.set('user', user.strip)
        event.set('src_ip', src_ip.strip)
        event.set('debug_field1', category)
    elsif category == 'web-proxy'
        data1 = arr1[1]
        #   0         1              2        3                  4                            5
        #account 0-Napbiotec: 192.168.20.115 GET http://cu.bwc.brother.com/certset/ver  action=allow cache=MISS        
        arr2 = data1.split(' ')
        src_ip = arr2[2]
        url = arr2[4]

        event.set('src_ip', src_ip.strip)
        event.set('domain', URI.parse(url).host)
        event.set('debug_field1', category)
    elsif category == 'dhcp'
        data1 = arr1[1]
        # 0        1         2      3           4         5       6   
        #info 0-Napbiotec: dhcp6 assigned 192.168.30.236 to E2:9B:9D:A9:DF:5B
        arr2 = data1.split(' ')
        src_ip = arr2[4]
        mac = arr2[6]

        event.set('src_ip', src_ip.strip)
        event.set('mac', mac)
        event.set('debug_field1', category)
    elsif category == 'firewall'
        arr1 = event.get('message').split(' ')
        #   0                1          2            3               4           5             6           7    8        9                          10                    11                
        # firewall,info 0-Napbiotec: forward: in:vlan20-office out:pppoe-tot, src-mac b4:0f:b3:1d:63:4b, proto TCP (ACK,FIN,PSH), 192.168.20.171:43996->47.241.18.42:443, NAT (192.168.20.171:43996->125.25.69.110:43996)->47.241.18.42:443, len 71

        src_networks = arr1[3].scan(/^\s*in:(.+?)$/i)[0]
        dst_networks = arr1[4].scan(/^\s*out:(.+?)$/i)[0]
        mac = arr1[6]
        ips = arr1[10].scan(/^\s*(.+?):(.+?)->(.+?):(.+?)$/i)[0]

        src_net = src_networks[0]
        dst_net = dst_networks[1]
        src_ip = ips[0]
        src_port = ips[1]
        dst_ip = ips[2]
        dst_port = ips[3]

        event.set('src_net', src_net.strip)
        event.set('dst_net', dst_net.strip)
        event.set('mac', mac.strip)
        event.set('src_ip', src_ip.strip)
        event.set('src_port', src_port.strip)
        event.set('dst_ip', dst_ip.strip)
        event.set('dst_port', dst_port.strip)
        event.set('debug_field1', category)
    end
    
    return [event]
end

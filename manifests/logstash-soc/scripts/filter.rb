#Example : https://fabianlee.org/2017/04/24/elk-using-ruby-in-logstash-filters/
#Labels {'user', 'domain', 'src_ip', 'dst_ip'}

def register(params)
    @category = params["category"]
end

def filter(event)
    arr1 = event.get('message').split(',')
    category = arr1[0]
    event.set('debug_field1', 'debug_field1')
    event.set('debug_field2', @category)

    if category == 'hotspot'
        data1 = arr1[2]
        arr2 = data1.split(':')
        data2 = arr2[1]
        event.set('user', data2)
        event.set('debug_field1', 'aaaaaaa')
    elsif category == 'web-proxy'
        data1 = arr1[1]
        #   0         1              2        3                  4                            5
        #account 0-Napbiotec: 192.168.20.115 GET http://cu.bwc.brother.com/certset/ver  action=allow cache=MISS
        arr2 = data1.split(' ')
        src_ip = arr2[2]
        url = arr2[4]

        event.set('src_ip', src_ip)
        event.set('url', url)
        event.set('debug_field1', 'bbbbbbbb')
    end

    return [event]
end

#Example : https://fabianlee.org/2017/04/24/elk-using-ruby-in-logstash-filters/
#Labels {'user', 'src_ip', 'dst_ip'}

def register(params)
    @category = params["category"]
end

def filter(event)
    if @category == 'hotspot'
        arr1 = event['message'].split(',')
        data1 = arr1[2]

        arr2 = data1.split(':')
        data2 = arr2[1]

        event['user'] = data2
    end

    return [event]
end

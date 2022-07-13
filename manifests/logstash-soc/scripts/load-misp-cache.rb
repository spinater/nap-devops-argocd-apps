def register(params)
    @cached_field = params["cached_field"]
    @value_field = params["value_field"]
    $stdout.sync = true
end

def filter(event)
    value = event.get(@value_field)
    misp_data = "This is cached data of [#{value}]"    

    puts "### Getting MISP from field [#{@value_field}] value [#{value}]"
    puts "### Loading MISP data to field [#{@cached_field}]\n"

    event.set(@cached_field, misp_data)
    return [event]
end

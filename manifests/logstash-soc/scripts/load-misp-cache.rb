def register(params)
    @cached_field = params["cached_field"]
    @value_field = params["value_field"]
    $stdout.sync = true
end

def filter(event)
    misp_data = '{"field":"this is MISP data"}'

    value = event.get(@value_field)

    puts "Getting MISP from field [#{@value_field}] value [#{value}]"
    puts "Load [#{misp_data}] to field [#{@cached_field}]"

    event.set(@cached_field, misp_data)
    return [event]
end

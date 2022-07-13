def register(params)
    @cached_field = params["cached_field"]
    @value_field = params["value_field"]
    $stdout.sync = true
end

def filter(event)
    value = event.get(@value_field)

    if value.nil? or value == ''
        misp_data = "Nothing to do because the field [#{@value_field}] is blank [#{value}]"
    else
        misp_data = "This is cached data of [#{value}]"

        puts "### [#{@cached_field}] Getting MISP from field [#{@value_field}] value [#{value}]"
    end

    event.set(@cached_field, misp_data)
    return [event]
end

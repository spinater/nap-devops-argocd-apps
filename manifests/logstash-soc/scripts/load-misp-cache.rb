def register(params)
    @cached_field = params["cached_field"]
end

def filter(event)
    event.set(@cached_field, '{}')
    return [event]
end

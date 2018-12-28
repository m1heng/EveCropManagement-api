def stdJSONresp( status, message,code , extra=None):
    response_body = {
        'status' = status,
        'message' = message
    }
    if extra:
        response_body.update(extra)
    return response_body, code
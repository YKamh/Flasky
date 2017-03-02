from flask import jsonify

from app.api_1_0 import api


def forbidden(message):
    response = jsonify({'error': 'forbidden', 'message': message})
    response.status_code = 403
    return response


@api.errorhandler(ValueError)
def validation_error(e):
    return bad_request(e.arg[0])



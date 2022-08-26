import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the database
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
'''
db_drop_and_create_all()

# ROUTES
'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks', methods=['GET'])
@requires_auth('get:drinks')
def get_drinks():
    drinks = Drink.query.all()

    if len(drinks) == 0:
        raise AuthError({
            'code': 'No Drink',
            'description': 'Drinks Empty'
        }, 400)

    return jsonify({
        'success': True,
        'drinks': [drink.short() for drink in drinks]
    }), 200


'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drink_detail():
    all_drinks = Drink.query.all()

    if len(all_drinks) == 0:
        raise AuthError({
            'code': 'No drink',
            'description': 'Drinks Empty'
        }, 400)

    return jsonify({
        'success': True,
        'drinks': [drink.long() for drink in all_drinks]
    }), 200


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def submit_drink():
    req_title = request.get_json()['title']
    req_recipe = request.get_json()['recipe']

    new_drink = Drink(title=req_title, recipe=json.dumps(req_recipe))

    try:
        new_drink.insert()
        posted_drink = Drink.query.filter(Drink.title == new_drink.title).one()
    except:
        raise AuthError({
            'code': 'Unprocessable Entity',
            'description': 'Drink could not be added'
        }, 422)

    return jsonify({
        'success': True,
        'drinks': posted_drink.long()
    }), 200


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(drink_id):
    current_drink = Drink.query.get(drink_id)

    body = request.get_json()

    if 'title' in body:
        current_drink.title = body['title']
    if 'recipe' in body:
        current_drink.recipe = body['recipe']

    if not current_drink:
        raise AuthError({
            'code': 'Drink not Found',
            'description': 'No such drink'
        }, 400)

    try:
        current_drink.update()
    except:
        raise AuthError({
            'code': 'Unprocessable Entity',
            'description': 'Drink could not be updated'
        }, 422)

    return jsonify({
        'success': True,
        'drinks': [current_drink.long()]
    }), 200


'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(drink_id):
    current_drink = Drink.query.get(drink_id)

    if not current_drink:
        raise AuthError({
            'code': 'Drink not Found',
            'description': 'No such drink'
        }, 400)

    if request.method != 'DELETE':
        raise AuthError({
            'code': 'Invalid method',
            'description': 'method delete is required at endpoint'
        }, 405)

    try:
        current_drink.delete()
    except:
        raise AuthError({
            'code': 'Unprocessable Entity',
            'description': 'drink could not be deleted'
        }, 422)

    return jsonify({
        'success': True,
        'delete': drink_id
    }), 200


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''


@app.errorhandler(405)
def missing_method(error):
    return jsonify({
        'success': False,
        'error': 405,
        'message': 'Invalid method'
    }), 405


@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'success': False,
        'error': 403,
        'message': 'forbidden'
    }), 403


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': 400,
        'message': 'Bad Request'
    }), 400


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        'success': False,
        'error': 500,
        'message': 'Internal Server error'
    }), 500


'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 404,
        'message': 'Resource Not Found'
    }), 404


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''


@app.errorhandler(AuthError)
def error(auth_err):
    return jsonify({
        'success': False,
        'error': auth_err.status_code,
        'message': auth_err.error.get('description')
    }), auth_err.status_code

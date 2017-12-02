from flask import Flask, jsonify, request, make_response, g
from flask_restful import Resource, Api
from pymongo import MongoClient
from utils.mongo_json_encoder import JSONEncoder
from bson.objectid import ObjectId
from bson.json_util import dumps
import bcrypt
import json
import pdb

# TODO: Commit
# TODO: Add documentation for each function and commit
# TODO: Slack juan the code. But only the things we did today.

app = Flask(__name__)
app.config['DEBUG'] = True

mongo = MongoClient('mongodb://uchennaaguocha:LakersKobe2408@ds049084.mlab.com:49084/trip_planner_production')
app.db = mongo.trip_planner_production

app.bcrypt_rounds = 12
## Write Resources here

def display_status(status_code, json=None):
    '''
        This function displays the status code of a network request.
        status_code: standard response codes given by client/backend servers on the Internet.
        json: formatted and transmitted data sent from one server to another server.
    '''
    return (json, status_code, None)
# TODO: look at this function
def check_user(username, password):
        users_collection = app.db.users
        user = users_collection.find_one( {'email': username} )

        if user is None:
            return False
    
        if bcrypt.checkpw(passwordcl.encode('utf-8'), user['password']):
            user.pop('password')
            return True
        else:
            return False

def request_auth(http_method):
        def wrapper(*args, **kwargs):
            email = request.authorization.username
            password = request.authorization.password


            if check_user(email, password) == True:
                return http_method(*args, **kwargs)

            else:
                return display_status(401)

        return wrapper

# def get(self):
#         '''
#         Shows all/specific users
#         '''
#         email = request.authorization.username
#         password = request.authorization.password
#         #user_id = request.args.get("id")
#         users_collection = app.db.users

#         # name = request.args.get("name")
#         # Find user by user_id
#         user = users_collection.find_one( {'email': request.authorization.username} )

#         # user.pop('password')
#         if user is None:
#             response = jsonify(data=[])
#             response.status_code = 404
#             return response
#         else:
#             # TODO: Verify that the password entered matches the hashed password in the db. Hint: Use checkpw function from bcrypt (In your notes)

#             return (user, 200, None)


class User(Resource):

    def post(self):
        '''
        Creates a new user

        '''
        new_user = request.json
        email = new_user['email']
        password = new_user['password']

        users_collection = app.db.users
        # users = users_collection.find_one( {"_id": ObjectId(result.inserted_id)} )
        user = users_collection.find_one( {"email": email} )


        # if email != user['email']:
        if user is None:
            encoded_password = password.encode('utf-8')

            hashed_password = bcrypt.hashpw(
                encoded_password, bcrypt.gensalt(app.bcrypt_rounds)
            )
            new_user['password'] = hashed_password
            results = users_collection.insert_one(new_user)
            new_user.pop('password')
            return(new_user, 200, None)
        else:
            return("Email is already taken", 409, None)
        
        #1 Fetch password from request.json
        #2 Fetch email and check if user already exists, emails should be unique

        #3 use extracted password and hash to new variable, remmeber to decode hash, cause it will return bytes type
        #4 Update dictionary that contains user post info (user_json = request.json), eg user_json['password'] = hashedpw
        #5 Save user_json dict to DB

        #1
        # new_user = request.json
        # users_collection = app.db.users

        # email = new_user["email"]
        # password = new_user["password"]
        # check_saved_user = users_collection.find_one( {"email": email} )
        # if email == check_saved_user:
        #     return("This email is taken.", 200, None)
        # if email != check_saved_user:
        #     encodedPassword = password.encode('utf-8')

        #     hashed = bcrypt.hashpw(
        #         encodedPassword, bcrypt.gensalt(app.bcrypt_rounds)
        #     )
        #     new_user["password"] = hashed.decode()
        #     result = users_collection.insert_one(new_user)

        # return(new_user, 200, None)


        # database_user = users_collection.find_one({'email': email})
        #
        # # Check if client password from login matches database password
        # if bcrypt.hashpw(jsonPassword, database_user['password']) == database_user['password']:
        #     ## Let them in
        # else:
        #     return("Wrong Password", 404, None)
        #     ## Tell user they have invaid credentials
        # #Data being send to the backend
        # new_user = request.json
        # #user collection exist in mongoDB
        # users_collection = app.db.users
        #
        # result = users_collection.insert_one(new_user)
        # #user = users_collection.find_one( {"_id": ObjectId(result.insert_id)} )
        #
        # return (new_user, 200, None)

            
    @request_auth
    def get(self):
        '''
        Shows all/specific users
        '''
        # user = g.get('user', None)
        # user.pop('password')
        # if not user:
        #   return()
        # pdb.set_trace()
        users_collection = app.db.users
        email = request.authorization.username
        user = users_collection.find_one( {"email": email} )
        user.pop('password')
        return (user, 200, None)

    def patch(self):
        '''
        Updates a specific user
        '''
        #JSON body
        user = request.json

        users_collection = app.db.users

        #name = request.args.get("name")

        user = users_collection.find_one_and_update(
            {"name": name},
            {"$set": user}
            )

        if user == None:
            response = jsonify(data=[])
            response.status_code = 404
            return response
        else:
            return (user, 200, None)

    def put(self, user_id):
        '''Find a user ID and replace it with a new ID'''
        user = request.json

        users_collection = app.db.users

        user = users_collection.find_one_and_replace(
            {"_id": ObjectId(user_id)},
        )

        if user is None:
            response = jsonify(data=[])
            response.status_code = 404
            return response
        else:
            return (user, 200, None)
    def delete(self, user_id):
        '''
        Deletes a specific user by their id or name
        '''
        users_collection = app.db.users

        name = request.args.get("name")
        user = users_collection.remove(
        {
            "_id": ObjectId(user_id),
            "name": name
        })
        return (user, 200, None)

class Trip(Resource):

    def __init__(self):
        self.trip_collection = app.db.trips

    def get(self):
        trips = request.args.get("trips")
        trip = self.trip_collection.find_one({"trips": trips})
        return (trip, 200, None)

    def post(self):
        new_trip = request.json

        trip = self.trip_collection.insert_one(new_trip)

        find_trip = self.trip_collection.find_one({"_id": trip.insert_id })
        return find_trip
    def patch(self, user_id=None):
        trip = request.json

        trip_collection = app.db.trips




api = Api(app)
api.add_resource(User, "/users")
api.add_resource(Trip, "/trips")

## Add api routes here

#  Custom JSON serializer for flask_restful
@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(JSONEncoder().encode(data), code)
    resp.headers.extend(headers or {})
    return resp

if __name__ == '__main__':
    # Turn this on in debug mode to get detailled information about request
    # related exceptions: http://flask.pocoo.org/docs/0.10/config/
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)

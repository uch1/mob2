import server
import unittest
import json
import bcrypt
import base64
from pymongo import MongoClient


class TripPlannerTestCase(unittest.TestCase):
    def setUp(self):

      self.app = server.app.test_client()
      # Run app in testing mode to retrieve exceptions and stack traces
      server.app.config['TESTING'] = True

      mongo = MongoClient('localhost', 27017)
      global db

      # Reduce encryption workloads for tests
      #server.app.bcrypt_rounds = 4

      db = mongo.test
      server.app.db = db

      db.drop_collection('users')
      db.drop_collection('trips')

    # User tests, fill with test methods

    def test_get_user(self):

        ## Post 2 users to database
        self.app.post('/user/',
                      headers=None,
                      data=json.dumps(dict(
                                           name="Uchenna Aguocha",
                                           email="uk.aguocha@example.com"
                                           )),
                                           content_type='application/json')

        ## 3 Make a get request to fetch the posted user
        response = self.app.get('/user/',query_string=dict(email="uk.aguocha@example.com"))

        # Decode reponse
        response_json = json.loads(response.data.decode())

                      ## Actual test to see if GET request was succesful
                      ## Here we check the status code

        self.assertEqual(response.status_code, 200)

    def test_post_user(self):
        self.app.post('/user/',
                        headers=None,
                        data=json.dumps(dict(
                                                name="Goku Son",
                                                email="goku.son@example.com")),
                                                content_type='application/json')
        ## Actual test to see if GET request was succesful
        ## Here we check the status code
        self.assertEqual(response.status_code, 200)

    def test_put_user(self):

        ## Post 2 users to database
        self.app.post('/user/',
                        headers=None,
                        data=json.dumps(dict(
                                                name="Goku Son",
                                                email="goku.son@example.com")),
                                                content_type='application/json')

        ## 3 Make a get request to fetch the posted user
        response = self.app.get('/user', query_string=dict(email="goku.son@example.com"))

        # Decode reponse
        response_json = json.loads(response.data.decode())

        ## Actual test to see if GET request was succesful
        ## Here we check the status code
        self.assertEqual(response.status_code, 200)
    def test_delete_user(self):

if __name__ == '__main__':
    unittest.main()

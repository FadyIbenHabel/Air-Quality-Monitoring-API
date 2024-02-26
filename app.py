from flask import Flask, jsonify, render_template, request, session, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_restful_swagger_2 import swagger
from flasgger import Swagger
import requests
from datetime import datetime
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token
from flask_session import Session
import os
import pathlib
from pip._vendor import cachecontrol

app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)
app.static_folder = 'static'
app.secret_key = "mysecretkey" 
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy()
migrate = Migrate(app, db)
db.init_app(app)
Session(app)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "" #google id removed
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@app.route('/')
def index():
    print("Session data:", session)
    if 'credentials' in session:  
        print("User is already logged in")
        print(f"User credentials: {session.get('credentials')}")
        print(f"User email: {session.get('email')}")

        return redirect("/home")
    else:
        print("User is not logged in")
        return render_template('index2.html')

@app.route('/login')
def login():
    # Generate and store the state
    #state = secrets.token_urlsafe(16)  # Generates a random URL-safe string
    authorization_url, state = flow.authorization_url()
    session["state"] = state

    return redirect(authorization_url)
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/callback')
def callback():
    # Continue with OAuth2 flow
    flow.fetch_token(authorization_response=request.url)

    # Verify if the state is missing or doesn't match
    if not session["state"] == request.args["state"]:
        abort(500) #state does not match


    credentials = flow.credentials

    # Create the token_request
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    # Verify the ID token
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # Store user information in the session
    session["credentials"] = credentials
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")

    return redirect("/home")

from functools import wraps

def login_is_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if 'credentials' not in session:
            return abort(401) 
        else:
            return function(*args, **kwargs)

    return decorated_function


@app.route('/home')
@login_is_required
def home():
    return render_template('index.html')
class AirQualityObservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city_name = db.Column(db.String(100), nullable=False)
    aqi = db.Column(db.Integer)
    co = db.Column(db.Float)
    pm10 = db.Column(db.Float)
    pm25 = db.Column(db.Float)
    o3 = db.Column(db.Float)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<AirQualityObservation {self.city_name} - AQI: {self.aqi} - CO: {self.co} - PM10: {self.pm10} - PM25: {self.pm25} - O3: {self.o3}>"
    
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class PollutionReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(255), nullable=False)
    pollution_type = db.Column(db.String(255), nullable=False)
    additional_comments = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
def fetch_data(city_name):
    api_key = "" #api key removed
    url = f"https://api.waqi.info/feed/{city_name}/?token={api_key}"
    response = requests.get(url)
    return response.json()
@app.route('/aqi/<city_name>', methods=['GET'])
@login_is_required
def get_aqi_by_city(city_name):
    try:
        aqi_data = fetch_data(city_name)

        # Check if the API request was successful
        if aqi_data['status'] == 'ok':
            data = aqi_data['data']

            # Store the fetched data in the database
            new_observation = AirQualityObservation(
                city_name=data['city']['name'],
                aqi=data['aqi'],
                timestamp=datetime.strptime(data['time']['s'], '%Y-%m-%d %H:%M:%S')
                )

            db.session.add(new_observation)
            db.session.commit()
            aqi_comment = get_aqi_comment(new_observation.aqi)
            return jsonify({'City_Name': new_observation.city_name, 'aqi': new_observation.aqi, 'status of the Air Quality': aqi_comment})
        else:
                return jsonify({'error': f'AQI data not found for {city_name}'}), 404

    except Exception as e:
        return jsonify({'error': f'Error retrieving AQI data: {str(e)}'}), 500
def get_aqi_comment(aqi):
    if aqi <= 50:
        return "Good"
    elif 50 < aqi <= 100:
        return "Moderate"
    elif 100 < aqi <= 150:
        return "Unhealthy for Sensitive Groups"
    elif 150 < aqi <= 200:
        return "Unhealthy"
    elif 200 < aqi <= 300:
        return "Very Unhealthy"
    else:
        return "Hazardous"



@app.route('/environmental_pollutants/<city_name>', methods=['GET'])
#@login_is_required
def get_ep_by_city(city_name):
    try:
        aqi_data = fetch_data(city_name)
        
        if aqi_data['status'] == 'ok':
            data = aqi_data['data']

            new_observation = AirQualityObservation(
                city_name=data['city']['name'],
                aqi=data['aqi'],
                co=data['iaqi']['co']['v'],
                pm10=data['iaqi']['pm10']['v'],
                pm25=data['iaqi']['pm25']['v'],
                o3=data['iaqi']['o3']['v'],
                timestamp=datetime.strptime(data['time']['s'], '%Y-%m-%d %H:%M:%S')
            )

            db.session.add(new_observation)
            db.session.commit()

            return jsonify({
                'City_Name': new_observation.city_name,
                'Monoxid CO':new_observation.co,
                'particulate matter 10': new_observation.pm10,
                'particulate matter 2.5': new_observation.pm25,
                'Ozone O3':new_observation.o3

            })

        else:
            return jsonify({'error': f'Environmental Pollutants measurement data not found for {city_name}'}), 404

    except Exception as e:
        return jsonify({'error': f'Error retrieving Environmental Pollutants measurement data: {str(e)}'}), 500
@app.route('/observations', methods=['GET'])
#@login_is_required
def get_all_observations():
    try:
        observations = AirQualityObservation.query.all()

        if observations:
            observation_list = []
            for observation in observations:
                observation_data = {
                    'City_Name': observation.city_name,
                    'AQI': observation.aqi,
                    'CO': observation.co,
                    'PM10': observation.pm10,
                    'PM25': observation.pm25,
                    'O3': observation.o3,
                    'Timestamp': observation.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                }
                observation_list.append(observation_data)

            return jsonify({'observations': observation_list})
        else:
            return jsonify({'error': 'No observations found'}), 404

    except Exception as e:
        return jsonify({'error': f'Error retrieving observations: {str(e)}'}), 500
@app.route('/post_feedback', methods=['POST'])
#@login_is_required
def submit_feedback():
    try:
        data = request.form

        new_feedback = Feedback(
            name=data['name'],
            email=data['email'],
            message=data['feedback']
        )

        db.session.add(new_feedback)
        db.session.commit()

        return jsonify({'message': 'Feedback submitted successfully'}), 201
    except Exception as e:
        # Log the error for debugging
        print(f'Error submitting feedback: {str(e)}')

        # Return a generic error message
        return jsonify({'error': 'Error submitting feedback. Please try again later.'}), 500
@app.route('/feedback_page')
#@login_is_required
def feedback_page():
    return render_template('feedback.html')
@app.route('/report_pollution', methods=['POST'])
#@login_is_required
def report_pollution():
    try:
        data = request.form
        print("Received data:", data)

        new_report = PollutionReport(
            location=data['location'],
            pollution_type=data['pollution_type'],
            additional_comments=data['additional_comments']
        )

        db.session.add(new_report)
        db.session.commit()
        report_id = new_report.id
        return jsonify({'message': 'Pollution report submitted successfully'}), 201
    except Exception as e:
        return jsonify({'error': f'Error submitting pollution report: {str(e)}'}), 500
@app.route('/report_page')
#@login_is_required
def report_page():
    return render_template('report.html')
@app.route('/get_current_report_id', methods=['GET'])
#@login_is_required
def get_current_report_id():
    try:
        # Fetch the maximum report ID from the database
        max_report_id = db.session.query(func.max(PollutionReport.id)).scalar()

        # If no reports exist, start from 1; otherwise, increment the max report ID
        current_report_id = 1 if max_report_id is None else max_report_id + 1

        return jsonify({'report_id': current_report_id-1}), 200
    except Exception as e:
        return jsonify({'error': f'Error getting current report ID: {str(e)}'}), 500
@app.route('/update_report_page')
#@login_is_required
def update_page():
  return render_template('update.html')

@app.route('/update_pollution_report/<int:report_id>', methods=['PUT'])
#@login_is_required
def update_pollution_report(report_id):
    try:
        data = request.form
        updated_comments = data.get('updated_comments')

        if not updated_comments:
            return jsonify({'error': 'Updated comments are required for the update.'}), 400

        report = PollutionReport.query.get(report_id)

        if report:
            # Update the comments and commit the changes
            report.additional_comments = updated_comments
            db.session.commit()

            return jsonify({'message': 'Pollution report updated successfully'}), 200
        else:
            return jsonify({'error': 'Pollution report not found'}), 404

    except Exception as e:
        return jsonify({'error': f'Error updating pollution report: {str(e)}'}), 500
    
@app.route('/delete_pollution_report/<int:report_id>', methods=['DELETE'])
#@login_is_required
def delete_pollution_report(report_id):
    try:
        report = PollutionReport.query.get(report_id)

        if report:
            # Delete the report and commit the changes
            db.session.delete(report)
            db.session.commit()

            return jsonify({'message': 'Pollution report deleted successfully'}), 200
        else:
            return jsonify({'error': 'Pollution report not found'}), 404

    except Exception as e:
        return jsonify({'error': f'Error deleting pollution report: {str(e)}'}), 500
@app.route('/delete_report_page')
#@login_is_required
def delete_page():
    return render_template('delete_report.html')



class AQIResource(Resource):
    def get(self, city_name):
        """
        Get AQI data by city name
        ---
        parameters:
          - name: city_name
            in: path
            type: string
            required: true
            description: City name
        responses:
          200:
            description: Success
            schema:
              type: object
              properties:
                City_Name:
                  type: string
                aqi:
                  type: integer
                status of the Air Quality:
                  type: string
          404:
            description: Not Found
        """
        try:
            aqi_data = fetch_data(city_name)

            # Check if the API request was successful
            if aqi_data['status'] == 'ok':
                data = aqi_data['data']

                # Mock storing the fetched data in the database
                new_observation = AirQualityObservation(
                    city_name=data['city']['name'],
                    aqi=data['aqi'],
                    timestamp=datetime.strptime(data['time']['s'], '%Y-%m-%d %H:%M:%S')
                )

                aqi_comment = get_aqi_comment(new_observation.aqi)
                response_data = {
                    'City_Name': new_observation.city_name,
                    'aqi': new_observation.aqi,
                    'status of the Air Quality': aqi_comment
                }

                # Convert Response object to a JSON-serializable format
                response_data = jsonify(response_data).get_json()

                return response_data, 200
            else:
                return jsonify({'error': f'AQI data not found for {city_name}'}), 404

        except Exception as e:
            return jsonify({'error': f'Error retrieving AQI data: {str(e)}'}), 500

api.add_resource(AQIResource, '/api/<string:city_name>')

class EnvironmentalPollutantsResource(Resource):
    def get(self, city_name):
        """
        Get environmental pollutants data by city name
        ---
        parameters:
          - name: city_name
            in: path
            type: string
            required: true
            description: City name
        responses:
          200:
            description: Success
            schema:
              type: object
              properties:
                City_Name:
                  type: string
                Monoxid CO:
                  type: float
                particulate matter 10:
                  type: float
                particulate matter 2.5:
                  type: float
                Ozone O3:
                  type: float
          404:
            description: Not Found
        """
        try:
            aqi_data = fetch_data(city_name)

            if aqi_data['status'] == 'ok':
                data = aqi_data['data']

                # Mock storing the fetched data in the database
                new_observation = AirQualityObservation(
                    city_name=data['city']['name'],
                    aqi=data['aqi'],
                    co=data['iaqi']['co']['v'],
                    pm10=data['iaqi']['pm10']['v'],
                    pm25=data['iaqi']['pm25']['v'],
                    o3=data['iaqi']['o3']['v'],
                    timestamp=datetime.strptime(data['time']['s'], '%Y-%m-%d %H:%M:%S')
                )

                return jsonify({
                    'City_Name': new_observation.city_name,
                    'Monoxid CO': new_observation.co,
                    'particulate matter 10': new_observation.pm10,
                    'particulate matter 2.5': new_observation.pm25,
                    'Ozone O3': new_observation.o3
                }), 200

            else:
                return jsonify({'error': f'Environmental Pollutants measurement data not found for {city_name}'}), 404

        except Exception as e:
            return jsonify({'error': f'Error retrieving Environmental Pollutants measurement data: {str(e)}'}), 500

api.add_resource(EnvironmentalPollutantsResource, '/environmental_pollutants/<string:city_name>')

class ObservationsResource(Resource):
    def get(self):
        """
        Get all air quality observations
        ---
        responses:
          200:
            description: Success
            schema:
              type: object
              properties:
                observations:
                  type: array
                  items:
                    type: object
                    properties:
                      City_Name:
                        type: string
                      AQI:
                        type: integer
                      CO:
                        type: float
                      PM10:
                        type: float
                      PM25:
                        type: float
                      O3:
                        type: float
                      Timestamp:
                        type: string
          404:
            description: Not Found
        """
        try:
            observations = AirQualityObservation.query.all()

            if observations:
                observation_list = []
                for observation in observations:
                    observation_data = {
                        'City_Name': observation.city_name,
                        'AQI': observation.aqi,
                        'CO': observation.co,
                        'PM10': observation.pm10,
                        'PM25': observation.pm25,
                        'O3': observation.o3,
                        'Timestamp': observation.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    observation_list.append(observation_data)

                return jsonify({'observations': observation_list}), 200
            else:
                return jsonify({'error': 'No observations found'}), 404

        except Exception as e:
            return jsonify({'error': f'Error retrieving observations: {str(e)}'}), 500

api.add_resource(ObservationsResource, '/observations')

class FeedbackResource(Resource):
    def post(self):
        """
        Submit Feedback
        ---
        tags:
          - Feedback
        parameters:
          - name: name
            in: formData
            type: string
            required: true
            description: Your name
          - name: email
            in: formData
            type: string
            required: true
            description: Your email
          - name: feedback
            in: formData
            type: string
            required: true
            description: Your feedback message
        responses:
          201:
            description: Feedback submitted successfully
          500:
            description: Error submitting feedback
        """
        try:
            data = request.form

            new_feedback = Feedback(
                name=data['name'],
                email=data['email'],
                message=data['feedback']
            )

            db.session.add(new_feedback)
            db.session.commit()

            return jsonify({'message': 'Feedback submitted successfully'}), 201
        except Exception as e:
            # Log the error for debugging
            print(f'Error submitting feedback: {str(e)}')

            # Return a generic error message
            return jsonify({'error': 'Error submitting feedback. Please try again later.'}), 500

class PollutionReportResource(Resource):
    def post(self):
        """
        Submit Pollution Report
        ---
        tags:
          - Pollution Report
        parameters:
          - name: location
            in: formData
            type: string
            required: true
            description: Location of pollution
          - name: pollution_type
            in: formData
            type: string
            required: true
            description: Type of pollution
          - name: additional_comments
            in: formData
            type: string
            description: Additional comments
        responses:
          201:
            description: Pollution report submitted successfully
          500:
            description: Error submitting pollution report
        """
        try:
            data = request.form

            new_report = PollutionReport(
                location=data['location'],
                pollution_type=data['pollution_type'],
                additional_comments=data['additional_comments']
            )

            db.session.add(new_report)
            db.session.commit()
            report_id = new_report.id
            return jsonify({'message': 'Pollution report submitted successfully'}), 201
        except Exception as e:
            return jsonify({'error': f'Error submitting pollution report: {str(e)}'}), 500
api.add_resource(FeedbackResource, '/post_feedback')
api.add_resource(PollutionReportResource, '/report_pollution')

class UpdatePollutionReportResource(Resource):
    def put(self, report_id):
        """
        Update Pollution Report
        ---
        tags:
          - Pollution Report
        parameters:
          - name: report_id
            in: path
            type: integer
            required: true
            description: ID of the pollution report to update
          - name: updated_comments
            in: formData
            type: string
            required: true
            description: Updated comments for the pollution report
        responses:
          200:
            description: Pollution report updated successfully
          400:
            description: Updated comments are required for the update
          404:
            description: Pollution report not found
          500:
            description: Error updating pollution report
        """
        try:
            data = request.form
            updated_comments = data.get('updated_comments')

            if not updated_comments:
                return jsonify({'error': 'Updated comments are required for the update.'}), 400

            report = PollutionReport.query.get(report_id)

            if report:
                # Update the comments and commit the changes
                report.additional_comments = updated_comments
                db.session.commit()

                return jsonify({'message': 'Pollution report updated successfully'}), 200
            else:
                return jsonify({'error': 'Pollution report not found'}), 404

        except Exception as e:
            return jsonify({'error': f'Error updating pollution report: {str(e)}'}), 500

class DeletePollutionReportResource(Resource):
    def delete(self, report_id):
        """
        Delete Pollution Report
        ---
        tags:
          - Pollution Report
        parameters:
          - name: report_id
            in: path
            type: integer
            required: true
            description: ID of the pollution report to delete
        responses:
          200:
            description: Pollution report deleted successfully
          404:
            description: Pollution report not found
          500:
            description: Error deleting pollution report
        """
        try:
            report = PollutionReport.query.get(report_id)

            if report:
                # Delete the report and commit the changes
                db.session.delete(report)
                db.session.commit()

                return jsonify({'message': 'Pollution report deleted successfully'}), 200
            else:
                return jsonify({'error': 'Pollution report not found'}), 404

        except Exception as e:
            return jsonify({'error': f'Error deleting pollution report: {str(e)}'}), 500

api.add_resource(UpdatePollutionReportResource, '/update_pollution_report/<int:report_id>')
api.add_resource(DeletePollutionReportResource, '/delete_pollution_report/<int:report_id>')

if __name__ == '__main__':
    app.run(debug=True)
#!flask/bin/python
from flask import Flask, jsonify, abort, make_response, request, url_for
from flask_sqlalchemy import SQLAlchemy
from app import app, db, models
import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = '2No_jQkUL-mdbne_0pmG6LRx '

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

@auth.get_password
def get_password(username):
    if username == 'matas':
        return 'slaptas'
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

# ---------------------------------------------------------- GET ----------------------------------------------------------
@app.route('/coaches', methods=['GET'])
@auth.login_required
def get_tasks3():
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    coaches = models.Coach.query.all()
    ats = ""
    cc = []
    for c in coaches:
        ats = str(c.id) + ' ' + c.name + ' ' + c.surname + ' ' + c.team
        cc.append(ats)
    return jsonify(cc)

@app.route('/players', methods=['GET'])
@auth.login_required
def get_tasks2():
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    players = models.Player.query.all()
    ats = ""
    pp = []
    for p in players:
        coach = p.trainer
        ats = str(p.id) + ' ' + p.name + ' ' + p.surname + ' ' + coach.team + ' ' + coach.name + ' ' + coach.surname
        pp.append(ats)
    return jsonify(pp)

# ------------------------------------------------------- GET by ID -------------------------------------------------------
@app.route('/coaches/<int:task_id>', methods=['GET'])
@auth.login_required
def get_task3(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    coach = models.Coach.query.get(task_id)
    if coach is None:
        abort(404)
    return jsonify(str(coach.id) + ' ' + coach.name + ' ' + coach.surname  + ' ' + coach.team)

@app.route('/players/<int:task_id>', methods=['GET'])
@auth.login_required
def get_task2(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    player = models.Player.query.get(task_id)
    if player is None:
        abort(404)
    return jsonify(str(player.id) + ' ' + player.name + ' ' + player.surname  + ' ' + player.trainer.team)

# ----------------------------------------------------- POST ----------------------------------------------------
@app.route('/coaches', methods=['POST'])
@auth.login_required
def create_task3():
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    if not request.json or not 'name' in request.json or not 'surname' in request.json or not 'team' in request.json:
        abort(400)
    c = models.Coach(name=request.json['name'], surname=request.json['surname'], team=request.json['team'])
    db.session.add( c )
    db.session.commit()
    return jsonify( str(c.id) + ' ' + c.name + ' ' + c.surname + ' ' + c.team), 201

@app.route('/players', methods=['POST'])
@auth.login_required
def create_task2():
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    if not request.json or not 'name' in request.json or not 'surname' in request.json or not 'height' in request.json or not 'weight' in request.json or not 'position' in request.json or not 'coach_id' in request.json:
        abort(400)
    c = models.Player(name=request.json['name'], surname=request.json['surname'], height=request.json['height'], weight=request.json['weight'], position=request.json['position'], coach_id=request.json['coach_id'])
    db.session.add( c )
    db.session.commit()
    coach = c.trainer
    return jsonify( str(c.id) + ' ' + c.name + ' ' + c.surname + ' ' + coach.team + ' ' + coach.name + ' ' + coach.surname), 201

# ----------------------------------------------------- PUT ---------------------------------------------------
@app.route('/coaches/<int:task_id>', methods=['PUT'])
@auth.login_required
def update_task3(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    coach = models.Coach.query.get(task_id)
    if coach is None:
        abort(404)
    if not request.json:
        abort(400)
    if 'name' in request.json:
        coach.name = request.json['name']

    if 'surname' in request.json:
        coach.surname = request.json['surname']
            
    if 'team' in request.json:
        coach.team = request.json['team']

    db.session.commit()
    return jsonify({'result': True})

@app.route('/players/<int:task_id>', methods=['PUT'])
@auth.login_required
def update_task2(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    player = models.Player.query.get(task_id)
    if player is None:
        abort(404)
    if not request.json:
        abort(400)
    if 'name' in request.json:
        player.name = request.json['name']
    if 'surname' in request.json:
        player.surname = request.json['surname']
    if 'height' in request.json:
        player.height = request.json['height']
    if 'weight' in request.json:
        player.weight = request.json['weight']
    if 'position' in request.json:
        player.position = request.json['position']
    if 'coach_id' in request.json:
        player.coach_id = request.json['coach_id']

    db.session.commit()
    return jsonify({'result': True})

# --------------------------------------------------- DELETE -------------------------------------------------
@app.route('/coaches/<int:task_id>', methods=['DELETE'])
@auth.login_required
def delete_task3(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    coach = [c for c in models.Coach.query.all() if c.id == task_id]
    if len(coach) == 0:
        abort(404)
    db.session.delete(coach[0])
    db.session.commit()
    return jsonify({'result': True})

@app.route('/players/<int:task_id>', methods=['DELETE'])
@auth.login_required
def delete_task2(task_id):
    #if 'credentials' not in flask.session:
        #return make_response(jsonify({'error': 'Unauthorized access'}), 401)
    #else:
    player = [p for p in models.Player.query.all() if p.id == task_id]
    if len(player) == 0:
        abort(404)
    db.session.delete(player[0])
    db.session.commit()
    return jsonify({'result': True})


# ---------------------------------------------------------- error wrappers to json
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)

# ---------------------------------------------------------- user friendly "id" implementation to url
def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task

@app.route('/')
def index():
  return print_index_table()


@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  drive = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  files = drive.files().list().execute()

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.jsonify(**files)


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/coaches">List of coaches</a></td>' +
          '</tr>' +
          '</td></tr>' +
          '<tr><td><a href="/players">List of players</a></td>' +
          '</tr>' +
         '<tr><td><a href="/coaches/1">Get coach by ID</a></td>' +
          '</tr>' +
          '</td></tr>' +
          '<tr><td><a href="/players/1">Get player by ID</a></td>' +
          '</tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')

# ---------------------------------------------------------- MAIN
if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run('localhost', 8080, debug=True)
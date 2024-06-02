from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from google.cloud.datastore.query import PropertyFilter

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

import io

app = Flask(__name__)
# app.secret_key = 'SECRET_KEY'
PHOTO_BUCKET='shinminy-photos'

client = datastore.Client()

# Values from Auth0 app
CLIENT_ID = 'UwMbKYBnpmLt0llj6KCe24AjGMCEm78e'
CLIENT_SECRET = 'BdXPqo3mg1sDcYfBII7MWWm8SHlFg6eGWNMPb4R_KvKXiSI4lSorNRXGGPZwu9qu'
DOMAIN = 'dev-cbqfbp3a02hqr6t2.us.auth0.com'

ALGORITHMS = ["RS256"]
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# databases
USERS = "users"
COURSES = "courses"
ENROLLMENTS = "enrollments"
AVATARS = "avatars"

course_properties = ["subject", "number", "title", "term", "instructor_id"]
error = {
    400: "The request body is invalid",
    401: "Unauthorized",
    403: "You don't have permission on this resource",
    404: "Not found",
    409: "Enrollment data is invalid"
    }

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def content_validation(content, code):
    # return True if content is valid
    if code == 400:
        return len(content) == len(course_properties)
    elif code == 403:
        return True if content is not None else False
    
    
@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"\
    
         
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "username" not in content or "password" not in content:
        return ({"Error": error[400]}, 400)
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    # incorrect username or password
    if "error" in r.json():
        return ({"Error": error[401]}, 401)
    
    res = {"token": r.json()["id_token"]}
    return res, 200, {'Content-Type':'application/json'}


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return 401
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return 401
    if unverified_header["alg"] == "HS256":
        return 401
    
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            return 401
        except jwt.JWTClaimsError:
            return 401
        except Exception:
            return 401

        return payload
    else:
        return 401

     
# Retrieve all users
@app.route("/users", methods=["GET"])
def get_all_users():
    payload = verify_jwt(request)
    
    # missing or invalid JWT
    if payload == 401:
        return ({"Error": error[401]}, 401)
    
    query = client.query(kind=USERS)    
    results = list(query.fetch())
    
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    check_role = list(query.fetch())
    # JWT doesn't belong to admin
    if check_role[0]["role"] != "admin":
        return ({"Error": error[403]}, 403)
    
    for result in results:
        result["id"] = result.key.id

    return (results, 200)


# Retrieve a specific user
@app.route("/" + USERS + "/<int:user_id>", methods=["GET"])
def get_user(user_id):
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    # valid JWT but user doesn't exist
    if not user or payload["sub"] != user["sub"]:
        return ({"Error": error[403]}, 403)
    
    # add "courses" property to output
    if user["role"] != "admin":
        user["courses"] = []
    if user["role"] == "instructor":
        # check courses instructor is teaching
        courses_query = client.query(kind=COURSES)
        courses_query.add_filter(filter=PropertyFilter('instructor_id', '=', user_id))
        courses = list(courses_query.fetch())
        for course in courses:
            url = request.base_url + "/courses/" + str(course.key.id)
            user["courses"].append(url)
    elif user["role"] == "student":
        # check classes student is enrolled in
        enroll_query = client.query(kind=ENROLLMENTS)    
        enroll_query.add_filter(filter=PropertyFilter('student_id', '=', user_id))
        enrollments = list(enroll_query.fetch())
        for enrollment in enrollments:
            url = request.root_url + "courses/" + str(enrollment["course_id"])
            user["courses"].append(url)
    
    # check avatar
    avatar_query = client.query(kind=AVATARS)    
    avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
    check_avatar = list(avatar_query.fetch())

    if check_avatar:
        url = request.url + "/avatar"
        user["avatar_url"] = url
    
    user["id"] = user.key.id
    return (user, 200)

# Create user avatar
@app.route("/" + USERS + "/<int:user_id>/avatar", methods=['POST'])
def create_avatar(user_id):
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return ({"Error": error[400]}, 400)

    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)
    
    # valid JWT but does not belong to user in path parameter
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    if payload["sub"] != user["sub"]:
        return ({"Error": error[403]}, 403)
    
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)
    
    # create/update Avatar entity, map filename to user_id
    avatar_query = client.query(kind=AVATARS) 
    avatar_query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
    curr_avatar = list(avatar_query.fetch())
    print(curr_avatar)
    if not curr_avatar:
        avatar = datastore.Entity(key=client.key(AVATARS))
    else:
        avatar = client.get(key=curr_avatar[0].key)
    avatar_content = {"filename": file_obj.filename, "user_id": user_id}
    avatar.update(avatar_content)
    client.put(avatar)
    
    return ({'avatar_url': request.url}, 200)


# Retrieve URL for user avatar
@app.route("/" + USERS + "/<int:user_id>/avatar", methods=['GET'])
def get_avatar(user_id):
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)
    
    # valid JWT but does not belong to user in path parameter
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    if payload["sub"] != user["sub"]:
        return ({"Error": error[403]}, 403)
    
    # user does not have avatar
    query = client.query(kind=AVATARS)
    query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
    user_avatar = list(query.fetch())
    if not user_avatar:
        return ({"Error": error[404]}, 404)

    filename = user_avatar[0]["filename"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(filename)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/png', download_name=filename)


# Delete user avatar
@app.route("/" + USERS + "/<int:user_id>/avatar", methods=['DELETE'])
def delete_avatar(user_id):
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)
    
    # valid JWT but does not belong to user in path parameter
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    if payload["sub"] != user["sub"]:
        return ({"Error": error[403]}, 403)
    
    # user does not have avatar
    query = client.query(kind=AVATARS)
    query.add_filter(filter=PropertyFilter('user_id', '=', user_id))
    user_avatar = list(query.fetch())
    if not user_avatar:
        return ({"Error": error[404]}, 404)

    filename = user_avatar[0]["filename"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(filename)
    # Delete the file from Cloud Storage
    blob.delete()
    # delete entity in Datastore
    client.delete(user_avatar[0].key)
    
    return ('', 204)


# Create a course
@app.route("/" + COURSES, methods=["POST"])
def post_course():
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)

    query = client.query(kind=USERS)    
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    check_role = list(query.fetch())
    
    # JWT doesn't belong to admin
    if check_role[0]["role"] != "admin":
        return ({"Error": error[403]}, 403)
    
    content = request.get_json()
    # validate content
    if not content_validation(content, 400):
        return ({"Error": error[400]}, 400)
    
    # validate instructor id
    instructor_key = client.key(USERS, content["instructor_id"])
    user = client.get(key=instructor_key)
    if user["role"] != "instructor":
        return ({"Error": error[400]}, 400) 

    # create course entity
    course = datastore.Entity(key=client.key(COURSES))
    update_content = {}
    for property in course_properties:
        update_content[property] = content[property]  
    course.update(update_content)
    client.put(course)
    
    # update id property for return to user
    course['id'] = course.key.id
    course['self'] = request.url + "/" + str(course.key.id)

    return (course, 201)
    
    
# Retrieve all courses
@app.route("/courses", methods=["GET"])
def get_all_courses():
    offset = request.args.get('offset')
    if offset is None:
        offset = 0
    offset = int(offset)
    
    query = client.query(kind=COURSES)  
    query.order = ["subject"]       # sort by subject
    course_iterator = query.fetch(limit=3, offset=offset)
    pages = course_iterator.pages
    results = list(next(pages))
    courses = {"courses" : []}
    for result in results:
        result['id'] = result.key.id
        result["self"] = request.base_url + '/' + str(result["id"])
        courses["courses"].append(result)
    
    next_offset = str(offset + 3)
    next_url = request.base_url + f'?offset={next_offset}&limit=3'
    courses["next"] = next_url
    
    return (courses, 200)


# Retrieve a specific course
@app.route("/" + COURSES + "/<int:course_id>", methods=["GET"])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    
    if not course:
        return ({"Error": error[404]}, 404)
    
    course['id'] = course.key.id
    course['self'] = request.url

    return (course, 200)


# Delete a specific course
# WIP: deletes enrollment of all students that were enrolled in the course
@app.route("/" + COURSES + "/<int:course_id>", methods=["DELETE"])
def delete_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)

    user_query = client.query(kind=USERS)    
    user_query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    check_role = list(user_query.fetch())
    
    # JWT doesn't belong to admin or course doesn't exist
    if check_role[0]["role"] != "admin" or not course:
        return ({"Error": error[403]}, 403)
    
    # get enrollment keys for course for deletion
    enroll_query = client.query(kind=ENROLLMENTS)    
    enroll_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
    check_enrollments = list(enroll.query.fetch())
    delete_keys = [course_key]
    for enrollment in check_enrollments:
        delete_keys.append(enrollment.key)
    
    client.delete_multi(delete_keys)
    
    return ("", 204)


# Update enrollment in a course
@app.route("/" + COURSES + "/<int:course_id>/students", methods=["PATCH"])
def update_enrollment(course_id):
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)

    # for checking credentials
    query = client.query(kind=USERS)    
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    check_role = list(query.fetch())
    
    # for checking if course exists + valid instructor id
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    
    if check_role[0]["role"] != "admin" or not course or (check_role[0]["role"] == "instructor" 
                                                          and course["instructor_id"] != check_role[0].key.id):
        return ({"Error": error[403]}, 403)

    content = request.get_json()

    # validate contents
    if "add" not in content or "remove" not in content:
        return ({"Error": error[409]}, 409)
    
    query = client.query(kind=USERS)  
    query.add_filter(filter=PropertyFilter('role', '=', 'student'))
    students = list(query.fetch())
    student_ids = []
    for student in students:
        student_ids.append(student.key.id)
    
    # action = add, remove
    for action, enroll_ids in content.items():
        for id in enroll_ids:
            if id not in student_ids:
                return ({"Error": error[409]}, 409)
            
            # get enrollment entity for student and course
            query = client.query(kind=ENROLLMENTS)    
            query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
            query.add_filter(filter=PropertyFilter('student_id', '=', id))
            current_enrollment = list(query.fetch())
            
            # duplicate ids between Add and Remove
            if action == "add":
                if id in content["remove"]:
                    return ({"Error": error[409]}, 409)
                # create new enrollment if not exists
                if not current_enrollment:
                    new_enrollment = datastore.Entity(key=client.key(ENROLLMENTS))
                    new_enrollment.update({"course_id": course_id, "student_id": id})
                    client.put(new_enrollment)
            elif action == "remove":
                # if id in content["add"]:
                #     return ({"Error": error[409]}, 409)
                # delete enrollment if exists
                if current_enrollment:
                    client.delete(current_enrollment[0].key)

    return ("", 200)


# Retrieve enrollment for a course
@app.route("/" + COURSES + "/<int:course_id>/students", methods=["GET"])
def get_enrollment(course_id):
    payload = verify_jwt(request)
    if payload == 401:
        return ({"Error": error[401]}, 401)
    
    
    # for checking credentials
    query = client.query(kind=USERS)    
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    check_role = list(query.fetch())
    
    # for checking if course exists + valid instructor id
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    
    if check_role[0]["role"] != "admin" or not course or (check_role[0]["role"] == "instructor" 
                                                          and course["instructor_id"] != check_role[0].key.id):
        return ({"Error": error[403]}, 403)
    
    query = client.query(kind=ENROLLMENTS)    
    query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
    students = list(query.fetch())

    return (students, 200)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)


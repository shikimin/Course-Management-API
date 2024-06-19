## Introduction
This REST API is designed for a hypothetical lightweight course management tool app similar to Canvas. 
9 Auth0 users have been pre-created for use with this API: 1 Admin, 2 Instructors, and 6 Students. 
Usernames are admin1@osu.com, instructor1@osu.com, student1@osu.com, and so forth. Passwords for all users is yoyo123!.
The application is hosted on Google Cloud Platform and uses Google App Engine and Datastore.

## Summary of Endpoints

| Functionality |    Endpoint   |  Protection  | Description |
| ------------- | ------------- | ------------- |------------- |
|  User Login   |  POST /users/login  | Pre-created Auth0 users with username and password  | Uses Auth0 to issue JWTs necessary for Authorization on all other endpoints |
| Get All Users |  GET /users  |  Admin only  |  Returns basic information of all 9 users |
|  Get a User  |  GET /users/:id  |  Admin or user with JWT that matches Google Datastore id | Returns detailed info about the user |
|  Create/update a user’s avatar  |  POST /users/:id/avatar  |  User with JWT that matches Google Datastore id  |  Uploads file to Google Cloud Storage  |
|  Get a user’s avatar  |  GET /users/:id/avatar  |  User with JWT that matches Google Datastore id  |  Reads and returns file from Google Cloud Storage  |
|  Delete a user’s avatar  |  DELETE /users/:id/avatar  |  User with JWT that matches Google Datastore id  |  Deletes file from Google Cloud Storage  |
|  Create a course  |  POST /courses  |  Admin only  |  Creates a course  |
|  Get all courses  |  GET /courses  |  Unprotected  |  Returns information of all courses ordered by subject.  |
|  Get a course  |  GET /course/:id  |  Unprotected  |  Returns information of a course  | 
|  Update a course  |  PATCH /course/:id  |  Admin only  |  Partially updates a course  |
|  Delete a course  |  DELETE /course/:id  |  Admin only  |  Deletes course and all enrollment info associated with course  |
|  Update enrollment in a course  |  PATCH /courses/:id/students  |  Admin or instructor of course  | Enrolls or unenrolls students from course  |
|  Get enrollment for a course  |  GET /courses/:id/students  |  Admin or instructor of course  | Returns all students enrolled in course  |

rest_gae
========

REST interface for NDB models over webapp2 in Google App Engine Python.

## About

Written and maintained by Yaron Budowski. Email me at: budowski@gmail.com.

A lot of authentication-related code was taken from [webapp2-user-accounts](https://github.com/abahgat/webapp2-user-accounts) by @abahgat.

To be used with Apache v2 license. Though it would be nice to hear about projects using this library (email me :-D).

## Example

```python

from rest_gae import *
from rest_gae.users import UserRESTHandler

class MyModel(ndb.Model):
  property1 = ndb.StringProperty()
  property2 = ndb.StringProperty()
  owner = ndb.KeyPropertyProperty(kind='User')
  
  class RESTMeta:
    user_owner_property = 'owner' # When a new instance is created, this property will be set to the logged-in user
    include_output_properties = ['property1'] # Only include these properties for output
  
app = webapp2.WSGIApplication([
    # Wraps MyModel with full REST API (GET/POST/PUT/DELETE)
    RESTHandler(
      '/api/mymodel', # The base URL for this model's endpoints
      MyModel, # The model to wrap
      permissions={
        'GET': PERMISSION_ANYONE,
        'POST': PERMISSION_LOGGED_IN_USER,
        'PUT': PERMISSION_OWNER_USER,
        'DELETE': PERMISSION_ADMIN
      },
      
      # Will be called for every PUT, right before the model is saved (also supports callbacks for GET/POST/DELETE)
      put_callback=lambda model, data: model
    ),

    # Optional REST API for user management
    UserRESTHandler(
        '/api/users',
        user_model=MyUser, # You can extend it with your own custom user class
        user_details_permission=PERMISSION_OWNER_USER,
        verify_email_address=True,
        verification_email={
            'sender': 'John Doe <john@doe.com>',
            'subject': 'Verify your email address',
            'body_text': 'Click here {{ user.full_name }}: {{ verification_url }}',
            'body_html': '<a href="{{ verification_url }}">Click here</a> {{ user.full_name }}'
            },
        verification_successful_url='/verification_successful',
        verification_failed_url='/verification_failed',
        reset_password_url='/reset_password',
        reset_password_email={
            'sender': 'John Doe <john@doe.com>',
            'subject': 'Please reset your password',
            'body_text': 'Reset here: {{ verification_url }}',
            'body_html': '<a href="{{ verification_url }}">Click here</a> to reset'
            },
        )
], debug=True, config=config)

```

## Features
##### REST API
* GET/POST/PUT/DELETE endpoints for NDB models (over webapp2) - JSON input/output.
* GET endpoint supports GQL querying, page fetching, ordering and results limits.
* Individually set permissions for each endpoint (e.g. only admins can delete a model; only the owning user can edit a model)
* When a model instance is created (using POST) - Automatically sets its owning user property
* Set which model properties should be included/excluded for REST endpoints
* Property name customization (e.g. "myprop" will be shown as "my_fancy_prop")
* Callback functions to be called during GET/POST/PUT/DELETE (for extra functionality/customization)
* X-HTTP-Method-Override support
* [CORS](https://developer.mozilla.org/en/docs/HTTP/Access_control_CORS) support
* Supports any webapp2 authentication compatible mechanism

##### User Management REST API
* Also includes a REST API for user management (to be used with rest_gae)
* GET/POST/PUT/DELETE endpoints for users
* Support for admin users (can manipulate other users' details freely)
* Can customize the built-in user class with additional properties
* Email verification (sends emails using GAE's email services or any other 3rd-party service)
* Password reset (by sending emails)

## Installation

1. Configure webapp2 for GAE
2. Configure [Jinja2](https://developers.google.com/appengine/docs/python/gettingstartedpython27/templates) for GAE
3. Include [dateutil](https://pypi.python.org/pypi/python-dateutil) with your app (make sure `import dateutil` works)
4. Drop-in the rest_gae folder

## Documentation

### RESTHandler

Should be used as part of the WSGIApplication routing:

```python
from rest_gae import * # This imports RESTHandler and the PERMISSION_ constants

app = webapp2.WSGIApplication([
    RESTHandler(
        '/api/mymodel', # The base API for this model's endpoints
        MyModel, # The model to wrap (can also be a string - e.g. `models.MyModel`)
        permissions={
            'GET': PERMISSION_ANYONE,
            'POST': PERMISSION_LOGGED_IN_USER,
            'PUT': PERMISSION_OWNER_USER,
            'DELETE': PERMISSION_ADMIN
        },
        get_callback=lambda model: model,
        post_callback=lambda model, data: model,
        put_callback=lambda model, data: model,
        delete_callback=lambda model: model,
        allow_http_method_override=False,
        allowed_origin='*'
    )
])
```

The `RESTHandler` adds the following REST endpoints (according to `permissions` parameter):
* **GET /mymodel** - returns all instances of MyModel (`PERMISSION_ANYONE` - all instances; `PERMISSION_OWNER_USER` - only the ones owned by the current logged-in user). See notes below on how to use the GET endpoint for advanced querying.
* **GET /mymodel/123** - returns information about a specific model instance (`PERMISSION_OWNER_USER` - only the owning user can view this information)
* **POST /mymodel** - creates a new MyModel instance 
* **PUT /mymodel/123** - updates an existing model's properties (`PERMISSION_OWNER_USER` - only the owning user can do that)
* **PUT /mymodel** - updates several model instances at once. The entire request is transactional - If one of the model update fails, any previous updates made in the same request will be undone.
* **DELETE /mymodel/123** - deletes a specific model (`PERMISSION_OWNER_USER` - only the owning user can do that)
* **DELETE /mymodel** - `PERMISSION_OWNER_USER`: deletes all model instances owned by the currently logged-in user; `PERMISSION_ADMIN` - deletes all model instances



Arguments the `RESTHandler` class constructor accepts:
* `url` - The base URL for all endpoints.
* `model` - The model class (can also be a string) that should be wrapped
* `permissions` - A dictionary of permissions (key=GET/POST/PUT/DELETE; value=PERMISSION_...). rest_gae uses webapp2_extras.auth to detect the currently logged-in user. Possible permissions:
  * `PERMISSION_ANYONE` - Anyone (even if not logged-in) can access this endpoint
  * `PERMISSION_LOGGED_IN_USER` - Must be a logged-in user to access this endpoint
  * `PERMISSION_OWNER_USER` - Must be the owner of the current model (used in PUT/DELETE endpoints). See notes below on how to specify the name of the Model property that marks the owning user.
  * `PERMISSION_ADMIN` - Must be an admin to access the current endpoint. See notes below on how to specify the name of the User model property that marks if a user is an admin or not.
* `get_callback` - (optional) If set, this function will be called just before returning the results:
  * In case of a GET /mymodel - the argument will be a list of model instances. The function must return a list of models, not necessarily the same as the input list (it can also be an empty list).
  * In case of a GET /mymodel/123 - the argument will be a single model instance. The function must return the model.
* `post_callback` - (optional) If set, this function will be called right after creating the model according to the input JSON data, and right before saving it (i.e. before model.put()).
The function receives two arguments: The model which will be saved; the raw input JSON dict (after it has gone through some pre-processing).
The function must return the model, in order for it to be saved. If the function raises an exception, the model creation fails with an error.
* `put_callback` - (optional) If set, this function will be called right after updating the model according to the input JSON data, and right before saving the updated model (i.e. before model.put()).
The function receives two arguments: The model which will be saved; the raw input JSON dict (after it has gone through some pre-processing).
The function must return the model, in order for it to be saved.
In case of multiple updates of models, this function will be called for each single model being updated.
If the function raises an exception, the model update fails with an error (in case of multi-update - the entire transaction fails).
* `delete_callback` - (optional) If set, this function will be called right before deleting a model. Receives an input argument of the model to be deleted. Function return value is ignored.
In case of multiple deletion of models, this function will be called for each single model being deleted.
If the function raises an exception, the model deletion fails with an error (in case of multi-delete - since there is no transaction, only the current deletion will fail and all previously-successful deletions will remain the same).
* `allow_http_method_override` - (optional; default=True) If set, allows the user to add an HTTP request header 'X-HTTP-Method-Override' to override the request type (e.g. if the HTTP request is a POST but it also contains 'X-HTTP-Method-Override: GET', it will be treated as a GET request).
* `allowed_origin` - (optional; default=None) If not set, CORS support is disabled. If set to '*' - allows Cross-Site HTTP requests from all domains; if set to 'http://sub.example.com' or similar - allows Cross-Site HTTP requests only from that domain. See [here](https://developer.mozilla.org/en/docs/HTTP/Access_control_CORS) for more information.


#### Advanced Querying using GET Endpoint
The `GET /mymodel` endpoint queries all of the model instances (or only the logged-in user's models - in case of `PERMISSION_OWNER_USER`). The endpoint accepts the following GET arguments:
* `q` - A GQL query. For example: `(prop1 > 300) and (prop2 < 500)`. See [here](https://developers.google.com/appengine/docs/python/datastore/gqlreference) for more info. **Note**: Make sure you URL-encode the value of this parameter (e.g. `(prop1=999) and (prop2>400)` becomes `%28prop1%3D999%29+and+%28prop2%3E400%29`).
* `order` - The order to sort the results by. Can be a comma-delimited list of property names. If a property name is prefixed with a minus sign, it means reverse order. For example: `prop1,-prop2,prop3`.
* `limit` - Indicates the maximum number of results to return (default = 1000).

The output of the GET endpoint looks like this:
```json
{ "results": [ ... ],
  "next_results_url": "http://example.com/mymodel?q=prop%3E666&limit=100&cursor=E-ABAIICLmoVZGV2fnBlcnNvbmFsbnV0cml0aW9uchULEghBY3Rpdml0eRiAgICAgPDbCAwU" }
```

* `results` - An array of results
* `next_results_url` - In case `limit` results have been returned and more results are available - this URL points to the next batch of results (will be equal to `null` if no more results).


#### Using PERMISSION_ADMIN
In order for gae_rest to know if the currently logged-in user is an admin or not, rest_gae assumes the User model has a BooleanProperty that indicates it:
```python
class MyUser(webapp2_extras.appengine.models.User):
    is_admin = ndb.BooleanProperty(default=False)
    
    class RESTMeta:
        # This is how rest_gae knows if a user is an admin or not
        admin_property = 'is_admin'
```

#### Using PERMISSION_OWNER_USER

If using `PERMISSION_OWNER_USER`, the model class MUST include a RESTMeta class with a `user_owner_property` defined. That property will be used in two cases:
* When verifying the ownership of the model (e.g. PUT to a specific model that is not owned by the currently logged-in user).
* When adding a new model (but not when updating) - that property will be assigned to the currently logged-in user. Note that this assignment works recursively for any StructuredProperty of the model (if that StructuredProperty's model has its own `user_owner_property` defined).

```python
class MyModel(ndb.Model):
    # When creating a new MyModel instance (using POST), this property will be set to the logged-in user.
    # Also, when trying to update/delete this model (using PUT/DELETE), in case of `PERMISSION_OWNER_USER`,
    # we'll verify that the logged-in user is in fact the owner of the model.
    owner = ndb.KeyProperty(kind='MyUser')
    
    class RESTMeta:
        user_owner_property = 'owner'
```

#### Filter Properties

You can choose which model properties will be displayed as JSON output, and which properties will be accepted as input:

```python
class MyModel(ndb.Model):
    prop1 = ndb.StringProperty()
    prop2 = ndb.StringProperty()
    prop3 = ndb.StringProperty()

    class RESTMeta:
        excluded_input_properties = ['prop1'] # Ignore input from users for these properties (these properties will be ignored on PUT/POST)
        excluded_output_properties = ['prop2'] # These properties won't be returned as output from the various endpoints
        excluded_properties = [ 'prop1', 'prop2' ] # Excluded properties - Both input and output together

        included_input_properties = ['prop1', 'prop3'] # Only these properties will be accepted as input from the user
        included_output_properties = ['prop1', 'prop3'] # Only these properties will returned as output
        included_properties = [ 'prop1', 'prop3' ] # Included properties - Both input and output together
```

#### Display Properties with a Different Name

You can define the names of properties, as they are displayed to the user or the way they're accepted as input:
```python
class MyModel(ndb.Model):
    prop1 = ndb.StringProperty()
    prop2 = ndb.StringProperty()
    prop3 = ndb.StringProperty()

    class RESTMeta:
        # All endpoints will display 'prop1' as 'new_prop1' and 'prop3' as 'new_prop3'
        translate_output_property_names = { 'prop1': 'new_prop1', 'prop3': 'new_prop3' }
        # All endpoints will accept 'new_prop2' instead of 'prop2' as input
        translate_input_property_names = { 'prop2': 'new_prop2' }
        # Translation table - both for input and output
        translate_property_names = { ... }
```



### UserRESTHandler

Should be used as part of the WSGIApplication routing:

```python
from rest_gae import * # This imports RESTHandler and the PERMISSION_ constants
from rest_gae.users import UserRESTHandler

# Make sure we initialize our WSGIApplication with this config (used for initializing webapp2_extras.sessions)
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'my-super-secret-key',
}

app = webapp2.WSGIApplication([
    UserRESTHandler(
        '/api/users', # The base URL for the user management endpoints
        user_model='models.MyUser', # Use our own custom User class
        email_as_username=True,
        admin_only_user_registration=True,
        user_details_permission=PERMISSION_LOGGED_IN_USER,
        verify_email_address=True,
        verification_email={
            'sender': 'John Doe <john@doe.com>',
            'subject': 'Verify your email',
            'body_text': 'Hello {{ user.full_name }}, click here: {{ verification_url }}',
            'body_html': 'Hello {{ user.full_name }}, click <a href="{{ verification_url }}">here</a>'
        },
        verification_successful_url='/verified-user',
        verification_failed_url='/verification-failed',
        reset_password_url='/reset-password',
        reset_password_email={
            'sender': 'John Doe <john@doe.com>',
            'subject': 'Reset your password',
            'body_text': 'Hello {{ user.name }}, click here: {{ verification_url }}',
            'body_html': 'Hello {{ user.name }}, click <a href="{{ verification_url }}">here</a>'
        },
        send_email_callback=my_send_email,
        allow_login_for_non_verified_email=False
   )], config=config)
```

This creates the following endpoints:
* **GET /users** - returns the listing of all users (for admins only) - can be used as a standard rest_gae GET endpoint (with limit, order and q parameters).
* **GET /users/123** - get a specific user's details (permitted according to `user_details_permission`).
* **POST /users** - registers a new user (if `admin_only_user_registration` == True - only admins can register).
* **POST /users/login** - logins using an email/user name+password combination. Returns a cookie-based token to be used in later calls.
* **POST /users/reset** - resets a user's password by sending him an email (the user name is passed in the POST data) - this endpoint is active only if `verify_email_address` is True.
* **GET /users/verify** - when a user registers (in case `verify_email_address` is True), an email with a verification link is sent to him - this is that link. Also used for password reset.
* **DELETE /users/123** - Deletes a user account (permitted for admins or if the user deletes his own account).
* **PUT /users/123** - updates an existing user's details (permitted for admins or if the user updates his own account). This also allows password change.
* **Note**: GET/POST/PUT/DELETE methods can be used with 'me' instead of the user ID (e.g. GET /users/me) as a shorthand for the currently logged-in user.

The UserRESTHandler constructor receives the following parameters:
* `user_model` - (optional) The user model to be used - if omitted, uses the default `rest_gae.users.User` model. **Note**: This model *MUST* inherit from rest_gae.users.User model.
* `email_as_username` - (optional; default=False) If true, will use the user's email as his user name.
* `admin_only_user_registration` - (optional; default=False) Only admins can register new users. In this, internally, you can use the `gae_rest.users.register_new_user` utility function for creating users.
* `user_details_permission` - (optional; default=`PERMISSION_OWNER_USER`) Defines who can view a specific user's details (anyone, any logged-in user, only the owning user or only admins).
* `verify_email_address` - (optional; default=False) Verifies a user's email address - will send an email with a verification link (its `user.is_email_verified` will be False until then).
The email is sent using GAE email services (see `send_email_callback` for using 3rd-party email sending services).
* `verification_email` - (optional) Must be set if `verify_email_address` is True. A dict containing the details of the verification email being sent:
  * `sender` - The sender's email address (in the format of `John Doe <john@doe.com>`). *Must* be an authorized GAE sender (i.e. that email address must be registered as the app's developer/owner).
  * `subject` - The email's subject line
  * `body_text` - The email's text content - a [Jinja2](http://jinja.pocoo.org/docs/) compatible template. Receives two input arguments: `user` and `verification_url`.
  * `body_html` - The email's HTML content - a [Jinja2](http://jinja.pocoo.org/docs/) compatible template. Receives two input arguments: `user` and `verification_url`.
* `verification_successful_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the email verification link and successfully verifying his email address.
* `verification_failed_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the email verification link, while the verification failed (happens when the link is outdated or the input params are invalid).
* `reset_password_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the reset password link. This page must show the user a new password form. When submitted, that page must call the `PUT /users/123` endpoint and update the password. It also has to provide that endpoint an additional `signup_token` parameter - so that we'll delete that token once the password has been set (so that the reset password link that wasn sent won't be active any more).
* `reset_password_email` - (optional) Must be set if `verify_email_address` is True. A dict containing the details of the reset password email being sent: Contains the same details as the `verification_email` dict.
* `send_email_callback` - (optional) If set, we'll use this function for sending out the emails for email verification / password reset (instead of using GAE's email services). The function receives a single dict argument - containing sender, subject, body_text, body_html. *Note*: The body_text + body_html values are already rendered as templates (meaning, the verification URLs are already embedded inside them).
* `allow_login_for_non_verified_email` - (optional; default=True) If set to False, any user with a non-verified email address will not be able to login (will get an access denied error).


#### Extending the User Class
You can extend the built-in User class, that comes prepared with the following properties: `is_admin`, `email`, `is_email_verified`:

```python
from rest_gae.users import User
class MyUser(User):
    """Our own user class"""
    prop1 = ndb.StringProperty(required=True)
    prop2 = ndb.StringProperty()
    
    # This is optional, but if we use a RESTMeta - we must inherit it (and not run over the original properties)
    class RESTMeta(User.RESTMeta):
        excluded_output_properties = User.RESTMeta.excluded_output_properties + ['prop2']
````



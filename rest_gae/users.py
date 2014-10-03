"""
REST API for user management (login, register, update and delete).
A lot of the webapp2 user authentication and registration implementation is based on: https://github.com/abahgat/webapp2-user-accounts
"""

import json
import time
from urllib import urlencode
import webapp2_extras.appengine.auth.models
import webapp2
from jinja2 import Template
from google.appengine.api import mail
from webapp2_extras import auth
from google.appengine.ext import ndb
from google.appengine.ext.ndb import model
from webapp2_extras import security
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras import sessions
from rest_gae import PERMISSION_ADMIN, PERMISSION_ANYONE, PERMISSION_LOGGED_IN_USER, PERMISSION_OWNER_USER, BaseRESTHandler, RESTException, import_class


def get_user_rest_class(**kwd):
    """Returns a USerRESTHandlerClass with the permissions set according to input"""

    class UserRESTHandlerClass(BaseRESTHandler):

        model = import_class(kwd.get('user_model', User))
        email_as_username = kwd.get('email_as_username', False)
        admin_only_user_registration = kwd.get('admin_only_user_registration', False)
        user_details_permission = kwd.get('user_details_permission', PERMISSION_OWNER_USER)
        verify_email_address = kwd.get('verify_email_address', False)
        verification_email = kwd.get('verification_email', None)
        verification_successful_url = kwd.get('verification_successful_url', None)
        verification_failed_url = kwd.get('verification_failed_url', None)
        reset_password_url = kwd.get('reset_password_url', None)
        reset_password_email = kwd.get('reset_password_email', None)
        user_policy_callback = [kwd.get('user_policy_callback', None)]
        send_email_callback = [kwd.get('send_email_callback', None)] # Wrapping in a list so the function won't be turned into a bound method
        allow_login_for_non_verified_email = kwd.get('allow_login_for_non_verified_email', True)

        # Validate arguments (we do this at this stage in order to raise exceptions immediately rather than while the app is running)
        if (model != User) and (User not in model.__bases__):
            raise ValueError('The provided user_model "%s" does not inherit from rest_gae.users.User class' % (model))
        if verify_email_address and not verification_email:
            raise ValueError('Must set "verification_email" when "verify_email_address" is True')
        if verification_email and set(verification_email.keys()) != set(['sender', 'subject', 'body_text', 'body_html']):
            raise ValueError('"verification_email" must include all of the following keys: sender, subject, body_text, body_html')
        if verify_email_address and not verification_successful_url:
            raise ValueError('Must set "verification_successful_url" when "verify_email_address" is True')
        if verify_email_address and not verification_failed_url:
            raise ValueError('Must set "verification_failed_url" when "verify_email_address" is True')
        if verify_email_address and not reset_password_url:
            raise ValueError('Must set "reset_password_url" when "verify_email_address" is True')
        if verify_email_address and not reset_password_email:
            raise ValueError('Must set "reset_password_email" when "verify_email_address" is True')
        if reset_password_email and set(reset_password_email.keys()) != set(['sender', 'subject', 'body_text', 'body_html']):
            raise ValueError('"reset_password_email" must include all of the following keys: sender, subject, body_text, body_html')


        permissions = { 'GET': PERMISSION_ANYONE, 'PUT': PERMISSION_OWNER_USER, 'DELETE': PERMISSION_OWNER_USER, 'POST': PERMISSION_ANYONE } # Used by get_response method when building the HTTP response header 'Access-Control-Allow-Methods'

        def __init__(self, request, response):
            self.initialize(request, response)

            self.send_email_callback = self.send_email_callback[0]

        def rest_method_wrapper(func):
            """Wraps GET/POST/PUT/DELETE methods and adds standard functionality"""

            def inner_f(self, model_id):
                # We make sure the auth session store is using the proper user model (we can't rely on the user initializing it from outside the library)
                self.auth.store.user_model = self.model

                method_name = func.func_name.upper()

                try:
                    # Call original method
                    if model_id:
                        model_id = model_id[1:] # Get rid of '/' at the beginning

                        if model_id == 'me':
                            # 'me' is shorthand for the currently logged-in user
                            if not self.user:
                                # User tried to retrieve information about himself without being logged-in
                                raise self.unauthorized()

                            model = self.user

                        elif (method_name == 'POST' and model_id in ['login', 'reset']) or (method_name == 'GET' and model_id == 'verify'):
                            model = model_id

                        else:
                            model = self._model_id_to_model(model_id)

                        return func(self, model)
                    else:
                        return func(self, None)

                except RESTException, exc:
                    return self.error(exc)

            return inner_f


        #
        # REST endpoint methods
        #


        @rest_method_wrapper
        def get(self, model):
            """GET endpoint - returns all users (if admin and not user id provided) or a specific user's details otherwise"""

            if not model:
                # Return all users (if admin)

                if not self.user:
                    # Must be logged-in
                    return self.unauthorized()
                if not self.user.is_admin:
                    # Must be an admin
                    return self.permission_denied()

                query = self._filter_query() # Filter the results
                query = self._order_query(query) # Order the results
                (results, cursor) = self._fetch_query(query) # Fetch them (with a limit / specific page, if provided)

                return self.success({
                    'results': results,
                    'next_results_url': self._build_next_query_url(cursor)
                    })


            elif model == 'verify':
                # It's an email verification link

                user_id = self.request.GET.get('user_id')
                signup_token = self.request.GET.get('signup_token')
                verification_type = self.request.GET.get('type')

                if not user_id or not signup_token or not verification_type:
                    return self.redirect(self.verification_failed_url)

                try:
                    user_id = int(user_id)
                except ValueError, exc:
                    return self.redirect(self.verification_failed_url)

                # it should be something more concise like
                # self.auth.get_user_by_token(user_id, signup_token)
                # unfortunately the auth interface does not (yet) allow to manipulate
                # signup tokens concisely
                try:
                    user, ts = self.user_model.get_by_auth_token(user_id, signup_token, 'signup')
                    if not user: raise Exception()
                except:
                    return self.redirect(self.verification_failed_url)

                # store user data in the session
                self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

                if verification_type == 'v':
                    # User verified his email address after registration

                    # Remove signup token, we don't want users to come back with an old link
                    self.user_model.delete_signup_token(user.get_id(), signup_token)

                    # Mark user's email address as verified
                    if not user.is_email_verified:
                        user.is_email_verified = True
                        user.put()

                    return self.redirect(self.verification_successful_url)

                elif verification_type == 'p':
                    # User wants to reset his password

                    # Redirect to password reset URL with the token
                    return self.redirect(self.reset_password_url + '?signup_token=' + signup_token)

                else:
                    # Unknown verification type
                    return self.redirect(self.verification_failed_url)


            # Return the details of a single user (by ID)

            if self.user_details_permission != PERMISSION_ANYONE:
                # Verify permissions

                if not self.user:
                    # Must be logged-in
                    return self.unauthorized()

                if (self.user_details_permission == PERMISSION_OWNER_USER) and (self.user != model) and (not self.user.is_admin):
                    # The owning user (and admins) is only one that can view his own user details
                    return self.permission_denied()

                if (self.user_details_permission == PERMISSION_ADMIN) and (not self.user.is_admin):
                    # Must be an admin
                    return self.permission_denied()


            # Return user details
            return self.success(model)


        @rest_method_wrapper
        def post(self, model):
            """POST endpoint - registers a new user"""

            if model and model not in ['login', 'reset']:
                # Invalid usage of the endpoint
                raise RESTException('Cannot POST to a specific user ID')

            if model and model == 'reset':
                # Send a password reset email

                try:
                    # Parse POST data as JSON
                    json_data = json.loads(self.request.body)
                except ValueError, exc:
                    raise RESTException('Invalid JSON POST data')

                if 'user_name' not in json_data:
                    raise RESTException('Missing user_name argument')

                user = self.user_model.get_by_auth_id(json_data['user_name'])
                if not user:
                    raise RESTException('User not found: %s' % json_data['user_name'])

                # Send the reset password email
                self._send_verification_email(user, self.reset_password_email, True)

                return self.success({})


            elif model and model == 'login':
                # Login the user

                try:
                    # Parse POST data as JSON
                    json_data = json.loads(self.request.body)
                except ValueError, exc:
                    raise RESTException('Invalid JSON POST data')

                if 'user_name' not in json_data:
                    raise RESTException('Missing user_name argument')
                if 'password' not in json_data:
                    raise RESTException('Missing password argument')

                try:
                    user = self.auth.get_user_by_password(json_data['user_name'], json_data['password'], remember=True, save_session=True)
                except (InvalidAuthIdError, InvalidPasswordError) as e:
                    # Login failed
                    return self.permission_denied('Invalid user name / password')

                if not self.allow_login_for_non_verified_email and not user.is_email_verified:
                    # Don't allow the user to login since he hasn't verified his email address yet.
                    return self.permission_denied('Email address not verified')

                # Login successful
                return self.success(user)


            #
            # Register a new user
            #


            if self.admin_only_user_registration:
                if not self.user:
                    # Must be logged-in
                    return self.unauthorized()

                if not self.user.is_admin:
                    # Must be admin
                    return self.permission_denied()


            try:
                # Parse POST data as JSON
                json_data = json.loads(self.request.body)
            except ValueError, exc:
                raise RESTException('Invalid JSON POST data')


            try:
                # Any exceptions raised due to invalid/missing input will be caught

                if self.user_policy_callback is not None and self.user_policy_callback[0] is not None:
                    json_data = self.user_policy_callback[0](self.user, json_data)

                if not 'email' in json_data:
                    raise ValueError('Missing email')
                if not self.email_as_username and not 'user_name' in json_data:
                    raise ValueError('Missing user_name')
                if not 'password' in json_data:
                    raise ValueError('Missing password')

                user_name = json_data['email'] if self.email_as_username else json_data['user_name']
                password = json_data['password']

                # Sanitize the input
                json_data.pop('user_name', None)
                json_data.pop('password', None)
                json_data.pop('is_email_verified', None)

                if self.user and self.user.is_admin:
                    # Allow admins to create a new user and set his access level
                    is_admin = json_data.get('is_admin', False)
                else:
                    is_admin = False

                json_data.pop('is_admin', None)


                user_properties = { }

                # Make sure only properties defined in the user model will be written (since the parent webapp2 User model is an ExpandoModel)
                for prop_name in self.model._properties.keys():
                    if prop_name in json_data:
                        user_properties[prop_name] = json_data[prop_name]

                unique_properties = ['email']

                user_data = self.model.create_user(
                        user_name,
                        unique_properties,
                        password_raw=password,
                        is_email_verified=(False if self.verify_email_address else True),
                        is_admin=is_admin,
                        **user_properties
                        )

                if not user_data[0]:
                    # Caused due to multiple keys (i.e. the user is already registered or the username/email is taken by someone else)
                    existing_fields = ['user_name' if s == 'auth_id' else s for s in user_data[1]]
                    raise RESTException('Unable to register user - the following fields are already registered: %s' % (', '.join(existing_fields)))


                if self.verify_email_address:
                    # Send email verification
                    user = user_data[1]
                    self._send_verification_email(user, self.verification_email)

                # Return the newly-created user
                return self.success(user_data[1])

            except Exception, exc:
                raise RESTException('Invalid JSON POST data - %s' % exc)


        def _send_verification_email(self, user, email, reset_password=False):
            """Sends a verification email to a specific `user` with specific email details (in `email`). Creates a reset password link if `reset_password` is True."""

            # Prepare the verification URL
            user_id = user.get_id()
            token = self.user_model.create_signup_token(user_id)

            path_url = self.request.path_url
            path_url = path_url[:-len('verify')] if path_url.endswith('reset') else path_url
            path_url = path_url.rstrip('/')
            verification_params = { 'type': ('v' if not reset_password else 'p'), 'user_id': user_id, 'signup_token': token }
            verification_url = path_url + '/verify?' + urlencode(verification_params)

            # Prepare email body
            email['body_text'] = Template(email['body_text']).render(user=user, verification_url=verification_url)
            email['body_html'] = Template(email['body_html']).render(user=user, verification_url=verification_url)

            # Send the email
            if self.send_email_callback:
                # Use the provided function for sending the email
                self.send_email_callback(email)
            else:
                # Use GAE's email services
                message = mail.EmailMessage()
                message.sender = email['sender']
                message.to = user.email
                message.subject = email['subject']
                message.body = email['body_text']
                message.html = email['body_html']
                message.send()


        @rest_method_wrapper
        def put(self, model):
            """PUT endpoint - updates a user's details"""

            if not model:
                # Invalid usage of the endpoint
                raise RESTException('Must provide user ID for PUT endpoint')


            if not self.user:
                # Must be logged-in
                return self.unauthorized()

            if (self.user != model) and (not self.user.is_admin):
                # The owning user (and admins) is only one that can update his own user details
                return self.permission_denied()


            try:
                # Parse PUT data as JSON
                json_data = json.loads(self.request.body)
            except ValueError, exc:
                raise RESTException('Invalid JSON PUT data')



            # Update the user
            try:
                # Any exceptions raised due to invalid/missing input will be caught

                if self.user_policy_callback is not None:
                    self.user_policy_callback[0](self.user, json_data)
                model = self._build_model_from_data(json_data, self.model, model)
                if self.user.is_admin:
                    # Allow the admin to change sensitive properties
                    if json_data.has_key('is_admin'):
                        model.is_admin = json_data['is_admin']
                    if json_data.has_key('is_email_verified'):
                        model.is_email_verified = json_data['is_email_verified']

                if json_data.has_key('password'):
                    # Change password if requested
                    model.set_password(json_data['password'])

                if json_data.has_key('signup_token'):
                    # Remove signup token (generated from a reset password link), we don't want users to come back with an old link
                    self.user_model.delete_signup_token(self.user.get_id(), json_data['signup_token'])

                model.put()

            except Exception, exc:
                raise RESTException('Invalid JSON PUT data - %s' % exc)


            # Return the updated user details
            return self.success(model)

        @rest_method_wrapper
        def delete(self, model):
            """DELETE endpoint - deletes an existing user"""

            if not model:
                # Invalid usage of the endpoint
                raise RESTException('Must provide user ID for DELETE endpoint')

            if not self.user:
                # Must be logged-in
                return self.unauthorized()

            if (self.user != model) and (not self.user.is_admin):
                # The owning user (and admins) is only one that can delete his own account
                return self.permission_denied()


            # Delete the user
            try:
                self.user_model.remove_unique(model.email, ['email'], email=model.email)
                model.key.delete()
            except Exception, exc:
                raise RESTException('Could not delete user - %s' % exc)


            # Return the deleted user instance
            return self.success(model)



    # Return the class statically initialized with given input arguments
    return UserRESTHandlerClass


class UserRESTHandler(webapp2.Route):
    """Returns our RequestHandler for user management. Should be used as part of the WSGIApplication routing:
            app = webapp2.WSGIApplication([('/users', UserRESTHandler(
                                                user_model='models.my_user_model',
                                                email_as_username=True,
                                                admin_only_user_registration=True,
                                                user_details_permission=PERMISSION_LOGGED_IN_USER,
                                                verify_email_address=True,
                                                verification_email={
                                                    'sender': 'John Doe <john@doe.com>',
                                                    'subject': 'Verify your email',
                                                    'body_text': 'Hello {{ user.name }}, click here: {{ verification_url }}',
                                                    'body_html': 'Hello {{ user.name }}, click <a href="{{ verification_url }}">here</a>'
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
                                                send_email_callback=lambda email: my_send_func(email),
                                                allow_login_for_non_verified_email=False
                                           )])

            This creates the following endpoints:
                GET /users - returns the listing of all users (for admins only) - can be used as a standard rest_gae GET endpoint (with limit, order and q parameters)
                GET /users/<user_id> - get the user details (permitted according to `user_details_permission`)
                POST /users - registers a new user (if `admin_only_user_registration` == True - only admins can register)
                POST /users/login - logins using an email/username+password combination
                POST /users/reset - resets a user's password by sending him an email (the user name is passed in the POST data) - this endpoint is active only if `verify_email_address` is True
                GET /users/verify - a link sent to a user's email address - for email verification (if `verify_email_address` is True) or for password reset
                DELETE /users/<user_id> - Deletes a user account (permitted for admins or if the user deletes his own account)
                PUT /users/<user_id> - updates an existing user's details (permitted for logged-in user or admins)
                GET/POST/PUT/DELETE methods can be used with 'me' (e.g. GET /users/me) as a shorthand for the currently logged-in user

        Parameters:
            `user_model` - (optional) The user model to be used - if omitted, uses the default rest_gae.users.User model. Note: This model MUST inherit from rest_gae.users.User model.
            `email_as_username` - (optional; default=False) If true, will use the user's email as his username
            `admin_only_user_registration` - (optional; default=False) Only admins can register new users. In this, internally, you can use the `register_new_user` utility method for creating users.
            `user_details_permission` - (optional; default=PERMISSION_OWNER_USER) Defines who can view a specific user's details (anyone, any logged-in user, only the owning user or the admin)
            `verify_email_address` - (optional; default=False) Verifies a user's email address - will send an email with a verification link (its user.is_email_verified will be False until then).
                    The email is sent using GAE email services. When this is set to True, you must set the `verification_email` parameter.
            `verification_email` - (optional) Must be set if `verify_email_address` is True. A dict containing the details of the verification email being sent:
                    `sender` - The sender's email address (in the format of "John Doe <john@doe.com>". Must be an authorized GAE sender (i.e. that email address must be registered
                                    as the app's developer/owner).
                    `subject` - The email's subject line
                    `body_text` - The email's text content - a Jinja2 compatible template. Receives two input arguments: `user` and `verification_url`.
                    `body_html` - The email's HTML content - a Jinja2 compatible template. Receives two input arguments: `user` and `verification_url`.
            `verification_successful_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the email verification link.
            `verification_failed_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the email verification link,
                                        while the verification failed (happens when the link is outdated or the input params are invalid).
            `reset_password_url` - (optional) Must be set if `verify_email_address` is True. The URL that the user will be redirected to after clicking the reset password link. This
                                    page must show the user a new password form. When submitted, that page must call the PUT /users/<id> API and update the password - and also provide it
                                    with an additional `signup_token` parameter - so that we'll delete that token once the password has been set.
            `reset_password_email` - (optional) Must be set if `verify_email_address` is True. A dict containing the details of the reset password email being sent: Contains the same
                                        details as the `verification_email` dict.
            `send_email_callback` - (optional) If set, we'll use this function for sending out the emails for email verification / password reset (instead of using GAE's email services).
                                        The function receives a single dict argument - containing sender, subject, body_text, body_html.
                                        Note that the body_text+body_html values are already rendered as templates (meaning, the verification URLs are already embedded inside them).
            `allow_login_for_non_verified_email` - (optional; default=True) If set to False, any user with a non-verified email address will not be able to login (will get an access denied error).

    """

    def __init__(self, url, **kwd):

        # Make sure we catch both URLs: to '/users' and to '/users/123' and '/users/login'
        super(UserRESTHandler, self).__init__(url.rstrip(' /') + '<model_id:(/.+)?|/>', get_user_rest_class(**kwd))



class User(webapp2_extras.appengine.auth.models.User):
    """The User class - you can inherit the class in order to extend it with additional properties/methods.
    Uses code from: https://github.com/abahgat/webapp2-user-accounts"""

    is_admin = ndb.BooleanProperty(default=False)
    email = ndb.StringProperty(required=False)
    is_email_verified = ndb.BooleanProperty(default=False)

    class RESTMeta:
        excluded_output_properties = ['password']
        excluded_input_properties = ['password', 'is_admin', 'is_email_verified' ]
        admin_property = 'is_admin'


    #
    # Authentication related methods
    #



    def set_password(self, raw_password):
      """Sets the password for the current user

      :param raw_password:
          The raw password which will be hashed and stored
      """
      self.password = security.generate_password_hash(raw_password, length=12)

    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
      """Returns a user object based on a user ID and token.

      :param user_id:
          The user_id of the requesting user.
      :param token:
          The token string to be verified.
      :returns:
          A tuple ``(User, timestamp)``, with a user object and
          the token timestamp, or ``(None, None)`` if both were not found.
      """
      token_key = cls.token_model.get_key(user_id, subject, token)
      user_key = ndb.Key(cls, user_id)
      # Use get_multi() to save a RPC call.
      valid_token, user = ndb.get_multi([token_key, user_key])
      if valid_token and user:
          timestamp = int(time.mktime(valid_token.created.timetuple()))
          return user, timestamp

      return None, None

    # Since the original create_user method calls user.put() (where the exception occurs), only *after*
    # calling cls.unique_model.create_multi(k for k, v in uniques), this means we'll have to delete
    # those created uniques (other they'll just stay as garbage data in the DB, while not allowing
    # the user to re-register with the same username/email/etc.
    @classmethod 
    def remove_unique(cls, auth_id, unique_properties, **user_values):
        uniques = [('%s.auth_id:%s' % (cls.__name__, auth_id), 'auth_id')]
        print uniques
        if unique_properties:
            for name in unique_properties:
                key = '%s.%s:%s' % (cls.__name__, name, user_values[name])
                uniques.append((key, name))

        # Delete the uniques
        ndb.delete_multi(model.Key(cls.unique_model, k) for k,v in uniques)


    @classmethod
    def create_user(cls, auth_id, unique_properties=None, **user_values):
        """Creates a new user (calls the original webapp2.auth.User.create_user. However, when the user
            creation fails due to an exception (e.g. when a required property isn't provided), we'll clean up
            and delete any unique properties created alongside the user model."""
        try:
            # Call original create_user method
            return super(User, cls).create_user(auth_id, unique_properties, **user_values)

        except Exception, exc:
            cls.remove_unique(auth_id, unique_properties, user_values)

            # Continue throwing the original exception
            raise exc


def register_new_user(user_name, email, password, **kwd):
    """Utility method for registering a new user. Useful for creating the first admin user. Returns the newly-created user.
    Can pass a `user_model` parameter to use a different User model.
    """
    user_model = import_class(kwd.pop('user_model', User))

    unique_properties = ['email']
    user_data = user_model.create_user(
            user_name,
            unique_properties,
            password_raw=password,
            email=email,
            **kwd
            )

    if not user_data[0]:
        raise ValueError('Unable to register user - the username "%s" or email "%s" is already registered' % (user_name, email))

    return user_data[1]




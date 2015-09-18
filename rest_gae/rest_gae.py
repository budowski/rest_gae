"""
Wraps NDB models and provided REST APIs (GET/POST/PUT/DELETE) arounds them.  Fully supports permissions.

Some code is taken from: https://github.com/abahgat/webapp2-user-accounts
"""

import importlib
import json
import re
from urlparse import urlparse
from datetime import datetime, time, date
from urllib import urlencode
import webapp2
from google.appengine.ext import ndb
from google.appengine.ext.ndb import Cursor
from google.appengine.ext.db import BadValueError, BadRequestError
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.routes import NamePrefixRoute
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import app_identity
from google.net.proto.ProtocolBuffer import ProtocolBufferDecodeError

try:
    import dateutil.parser
except ImportError as e:
    dateutil = None


# The REST permissions
PERMISSION_ANYONE = 'anyone'
PERMISSION_LOGGED_IN_USER = 'logged_in_user'
PERMISSION_OWNER_USER = 'owner_user'
PERMISSION_ADMIN = 'admin'



class NDBEncoder(json.JSONEncoder):
    """JSON encoding for NDB models and properties"""
    def _decode_key(self, key):
            model_class = ndb.Model._kind_map.get(key.kind())
            if getattr(model_class, 'RESTMeta', None) and getattr(model_class.RESTMeta, 'use_input_id', False):
                return key.string_id()
            else:
                return key.urlsafe()

    def default(self, obj):
        if isinstance(obj, ndb.Model):
            obj_dict = obj.to_dict()

            # Each BlobKeyProperty is represented as a dict of upload_url/download_url
            for (name, prop) in obj._properties.iteritems():
                if isinstance(prop, ndb.BlobKeyProperty):
                    server_host = app_identity.get_default_version_hostname()
                    blob_property_url = 'http://%s%s/%s/%s' % (server_host, obj.RESTMeta.base_url, self._decode_key(obj.key), name) # e.g. /api/my_model/<SOME_KEY>/blob_prop
                    obj_dict[name] = {
                            'upload_url': blob_property_url,
                            'download_url': blob_property_url if getattr(obj, name) else None # Display as null if the blob property is not set
                            }



            # Filter the properties that will be returned to user
            included_properties = get_included_properties(obj, 'output')
            obj_dict = dict((k,v) for k,v in obj_dict.iteritems() if k in included_properties)
            # Translate the property names
            obj_dict = translate_property_names(obj_dict, obj, 'output')
            obj_dict['id'] = self._decode_key(obj.key)

            return obj_dict

        elif isinstance(obj, datetime) or isinstance(obj, date) or isinstance(obj, time):
            return obj.isoformat()

        elif isinstance(obj, ndb.Key):
            return self._decode_key(obj)

        elif isinstance(obj, ndb.GeoPt):
            return str(obj)

        else:
            return json.JSONEncoder.default(self, obj)

class RESTException(Exception):
    """REST methods exception"""
    pass


class NoResponseResult(object):
    """A class representing a non-response - used by rest_method_wrapper to detect when we shouldn't print any data with response.write.
    Used when serving blobs (for BlobKeyProperty)"""
    pass


#
# Utility functions
#


def get_translation_table(model, input_type):
    """Returns the translation table for a given `model` with a given `input_type`"""
    meta_class = getattr(model, 'RESTMeta', None)
    if not meta_class:
        return {}

    translation_table = getattr(model.RESTMeta, 'translate_property_names', {})
    translation_table.update(getattr(model.RESTMeta, 'translate_%s_property_names' % input_type, {}))

    return translation_table



def translate_property_names(data, model, input_type):
    """Translates property names in `data` dict from one name to another, according to what is stated in `input_type` and the model's
    RESTMeta.translate_property_names/translate_input_property_names/translate_output_property_name - note that the change of `data` is in-place."""

    translation_table = get_translation_table(model, input_type)

    if not translation_table:
        return data


    # Translate from one property name to another - for output, we turn the original property names
    # into the new property names. For input, we convert back from the new property names to the original
    # property names.
    for old_name, new_name in translation_table.iteritems():
        if input_type == 'output' and old_name not in data: continue
        if input_type == 'input' and new_name not in data: continue

        if input_type == 'output':
            original_value = data[old_name]
            del data[old_name]
            data[new_name] = original_value

        elif input_type == 'input':
            original_value = data[new_name]
            del data[new_name]
            data[old_name] = original_value

    return data

def get_included_properties(model, input_type):
    """Gets the properties of a `model` class to use for input/output (`input_type`). Uses the
    model's Meta class to determine the included/excluded properties."""

    meta_class = getattr(model, 'RESTMeta', None)

    included_properties = set()

    if meta_class:
        included_properties = set(getattr(meta_class, 'included_%s_properties' % input_type, []))
        included_properties.update(set(getattr(meta_class, 'included_properties', [])))

    if not included_properties:
        # No Meta class (or no included properties defined), assume all properties are included
        included_properties = set(model._properties.keys())

    if meta_class:
        excluded_properties = set(getattr(meta_class, 'excluded_%s_properties' % input_type, []))
        excluded_properties.update(set(getattr(meta_class, 'excluded_properties', [])))
    else:
        # No Meta class, assume no properties are excluded
        excluded_properties = set()

    # Add some default excluded properties
    if input_type == 'input':
        excluded_properties.update(set(BaseRESTHandler.DEFAULT_EXCLUDED_INPUT_PROPERTIES))
        if meta_class and getattr(meta_class, 'use_input_id', False):
            included_properties.update(['id'])
    if input_type == 'output':
        excluded_properties.update(set(BaseRESTHandler.DEFAULT_EXCLUDED_OUTPUT_PROPERTIES))

    # Calculate the properties to include
    properties = included_properties - excluded_properties

    return properties


def import_class(input_cls):
    """Imports a class (if given as a string) or returns as-is (if given as a class)"""

    if not isinstance(input_cls, str):
        # It's a class - return as-is
        return input_cls

    try:
        (module_name, class_name) = input_cls.rsplit('.', 1)
        module = __import__(module_name, fromlist=[class_name])
        return getattr(module, class_name)
    except Exception, exc:
        # Couldn't import the class
        raise ValueError("Couldn't import the model class '%s'" % input_cls)


class BaseRESTHandler(webapp2.RequestHandler):
    """Base request handler class for REST handlers (used by RESTHandlerClass and UserRESTHandlerClass)"""


    # The default number of results to return for a query in case `limit` parameter wasn't provided by the user
    DEFAULT_MAX_QUERY_RESULTS = 1000

    # The names of properties that should be excluded from input/output
    DEFAULT_EXCLUDED_INPUT_PROPERTIES = [ 'class_' ] # 'class_' is a PolyModel attribute
    DEFAULT_EXCLUDED_OUTPUT_PROPERTIES = [ ]


    #
    # Session related methods/properties
    #


    def dispatch(self):
        """Needed in order for the webapp2 sessions to work"""

        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            if getattr(self, 'allow_http_method_override', False) and ('X-HTTP-Method-Override' in self.request.headers):
                # User wants to override method type
                overridden_method_name = self.request.headers['X-HTTP-Method-Override'].upper().strip()
                if overridden_method_name not in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']:
                    return self.method_not_allowed()

                self.request.method = overridden_method_name


            if getattr(self, 'allowed_origin', None):
                allowed_origin = self.allowed_origin

                if 'Origin' in self.request.headers:
                    # See if the origin matches
                    origin = self.request.headers['Origin']

                    if (origin != allowed_origin) and (allowed_origin != '*'):
                        return self.permission_denied('Origin not allowed')


            # Dispatch the request.
            response = webapp2.RequestHandler.dispatch(self)

        except:
            raise
        else:
            # Save all sessions.
            self.session_store.save_sessions(response)

        return response


    @webapp2.cached_property
    def session(self):
        """Shortcut to access the current session."""
        backend = self.app.config.get("session_backend", "datastore")
        return self.session_store.get_session(backend=backend)



    #
    # Authentication methods/properties
    #


    @webapp2.cached_property
    def auth(self):
        """Shortcut to access the auth instance as a property."""
        return auth.get_auth()


    @webapp2.cached_property
    def user_info(self):
        """Shortcut to access a subset of the user attributes that are stored
        in the session.

        The list of attributes to store in the session is specified in
          config['webapp2_extras.auth']['user_attributes'].
        :returns
          A dictionary with most user information
        """
        return self.auth.get_user_by_session()

    @webapp2.cached_property
    def user_model(self):
        """Returns the implementation of the user model.

        It is consistent with config['webapp2_extras.auth']['user_model'], if set.
        """
        return self.auth.store.user_model

    @webapp2.cached_property
    def user(self):
        """Shortcut to access the current logged in user.

        Unlike user_info, it fetches information from the persistence layer and
        returns an instance of the underlying model.

        :returns
          The instance of the user model associated to the logged in user.
        """
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None


    #
    # HTTP response helper methods
    #


    def get_response(self, status, content):
        """Returns an HTTP status message with JSON-encoded content (and appropriate HTTP response headers)"""

        # Create the JSON-encoded response
        response = webapp2.Response(json.dumps(content, cls=NDBEncoder))

        response.status = status

        response.headers['Content-Type'] = 'application/json'
        response.headers['Access-Control-Allow-Methods'] = ', '.join(self.permissions.keys())

        if getattr(self, 'allowed_origin', None):
            response.headers['Access-Control-Allow-Origin'] = self.allowed_origin

        return response

    def success(self, content):
        return self.get_response(200, content)

    def error(self, exception):
        return self.get_response(400, {'error': str(exception)})

    def method_not_allowed(self):
        return self.get_response(405, {})

    def permission_denied(self, reason=None):
        return self.get_response(403, { 'reason': reason})

    def unauthorized(self):
        return self.get_response(401, {})

    def redirect(self, url, **kwd):
        return webapp2.redirect(url, **kwd)



    #
    # Utility methods
    #


    def _model_id_to_model(self, model_id):
        """Returns the model according to the model_id; raises an exception if invalid ID / model not found"""

        if not model_id:
            return None

        try:
            if getattr(self.model, 'RESTMeta', None) and getattr(self.model.RESTMeta, 'use_input_id', False):
                model = ndb.Key(self.model, model_id).get()
            else:
                model = ndb.Key(urlsafe=model_id).get()
            if not model: raise Exception()
        except Exception, exc:
            # Invalid key name
            raise RESTException('Invalid model id - %s' % model_id)

        return model


    def _build_next_query_url(self, cursor):
        """Returns the next URL to fetch results for - used when paging. Returns none if no more results"""
        if not cursor:
            return None

        # Use all of the original query arguments - just override the cursor argument
        params = self.request.GET
        params['cursor'] = cursor.urlsafe()
        return self.request.path_url + '?' + urlencode(params)

    def _filter_query(self):
        """Filters the query results for given property filters (if provided by user)."""

        if not self.request.GET.get('q'):
            # No query given - return as-is
            return self.model.query()

        try:
            # Translate any property names
            translation_table = get_translation_table(self.model, 'input')

            query = self.request.GET.get('q')

            for original_name, new_name in translation_table.iteritems():
                # Replace any references to the new property name with the old (original) one
                query = re.sub(r'\b%s\s*(<=|>=|=|<|>|!=|(\s+IN\s+))' % new_name, r'%s \1' % original_name, query, flags=re.IGNORECASE)

            return self.model.gql('WHERE ' + query)
        except Exception, exc:
            # Invalid query
            raise RESTException('Invalid query param - "%s"' % self.request.GET.get('q'))


    def _fetch_query(self, query):
        """Fetches the query results for a given limit (if provided by user) and for a specific results page (if given by user).
        Returns a tuple of (results, cursor_for_next_fetch). cursor_for_next_fetch will be None is no more results are available."""

        if not self.request.GET.get('limit'):
            # No limit given - use default limit
            limit = BaseRESTHandler.DEFAULT_MAX_QUERY_RESULTS
        else:
            try:
                limit = int(self.request.GET.get('limit'))
                if limit <= 0: raise ValueError('Limit cannot be zero or less')
            except ValueError, exc:
                # Invalid limit value
                raise RESTException('Invalid "limit" parameter - %s' % self.request.GET.get('limit'))

        if not self.request.GET.get('cursor'):
            # Fetch results from scratch
            cursor = None
        else:
            # Continue a previous query
            try:
                cursor = Cursor(urlsafe=self.request.GET.get('cursor'))
            except BadValueError, exc:
                raise RESTException('Invalid "cursor" argument - %s' % self.request.GET.get('cursor'))

        try:
            (results, cursor, more_available) = query.fetch_page(limit, start_cursor=cursor)
        except BadRequestError, exc:
            # This happens when we're using an existing cursor and the other query arguments were messed with
            raise RESTException('Invalid "cursor" argument - %s' % self.request.GET.get('cursor'))

        if not more_available:
            cursor = None

        return (results, cursor)


    def _order_query(self, query):
        """Orders the query if input given by user. Returns the modified, sorted query"""

        if not self.request.GET.get('order'):
            # No order given
            orders = []

        else:
            try:
                # The order parameter is formatted as 'col1, -col2, col3'
                orders = [o.strip() for o in self.request.GET.get('order').split(',')]
                orders = ['+'+o if not o.startswith('-') and not o.startswith('+') else o for o in orders]

                # Translate property names (if it's defined for the current model) - e.g. input 'col1' is actually 'my_col1' in MyModel
                translated_orders = dict([order.lstrip('-+'), order[0]] for order in orders)
                translated_orders = translate_property_names(translated_orders, self.model, 'input')

                orders = [-getattr(self.model, order) if direction == '-' else getattr(self.model, order) for order,direction in translated_orders.iteritems()]

            except AttributeError, exc:
                # Invalid column name
                raise RESTException('Invalid "order" parameter - %s' % self.request.GET.get('order'))

        # Always use a sort-by-key order at the end - this solves the case where the query uses IN or != operators - since we're using a cursor
        # to fetch results - there is a requirement for this solution in order for the fetch_page to work. See "Query cursors" at
        # https://developers.google.com/appengine/docs/python/ndb/queries
        orders.append(self.model.key)

        # Return the ordered query
        return query.order(*orders)


    def _build_model_from_data(self, data, cls, model=None):
        """Builds a model instance (according to `cls`) from user input and returns it. Updates an existing model instance if given.
        Raises exceptions if input data is invalid."""

        # Translate the property names (this is done before the filtering in order to get the original property names by which the filtering is done)
        data = translate_property_names(data, cls, 'input')

        # Transform any raw input data into appropriate NDB properties - write all transformed properties
        # into another dict (so any other unauthorized properties will be ignored).
        input_properties = { }
        for (name, prop) in cls._properties.iteritems():
            if name not in data: continue # Input not given by user

            if prop._repeated:
                # This property is repeated (i.e. an array of values)
                input_properties[name] = [self._value_to_property(value, prop) for value in data[name]]
            else:
                input_properties[name] = self._value_to_property(data[name], prop)

        if not model and getattr(cls, 'RESTMeta', None) and getattr(cls.RESTMeta, 'use_input_id', False):
            if 'id' not in data:
                raise RESTException('id field is required')
            input_properties['id'] = data['id']

        # Filter the input properties
        included_properties = get_included_properties(cls, 'input')
        input_properties = dict((k,v) for k,v in input_properties.iteritems() if k in included_properties)

        # Set the user owner property to the currently logged-in user (if it's defined for the model class) - note that we're doing this check on the input `cls` parameter
        # and not the self.model class, since we need to support when a model has an inner StructuredProperty, and that model has its own RESTMeta definition.
        if hasattr(cls, 'RESTMeta') and hasattr(cls.RESTMeta, 'user_owner_property'):
            if not model and self.user:
                # Only perform this update when creating a new model - otherwise, each update might change this (very problematic in case an
                # admin updates another user's model instance - it'll change model ownership from that user to the admin)
                input_properties[cls.RESTMeta.user_owner_property] = self.user.key

        if not model:
            # Create a new model instance
            model = cls(**input_properties)
        else:
            # Update an existing model instance
            model.populate(**input_properties)

        return model

    def _value_to_property(self, value, prop):
        """Converts raw data value into an appropriate NDB property"""
        if isinstance(prop, ndb.KeyProperty):
            if value is None:
                return None
            try:
                return ndb.Key(urlsafe=value)
            except ProtocolBufferDecodeError as e:
                if prop._kind is not None:
                    model_class = ndb.Model._kind_map.get(prop._kind)
                    if getattr(model_class, 'RESTMeta', None) and getattr(model_class.RESTMeta, 'use_input_id', False):
                        return ndb.Key(model_class, value)
            raise RESTException('invalid key: {}'.format(value) )
        elif isinstance(prop, ndb.TimeProperty):
            if dateutil is None:
                try:
                    return datetime.strptime(value, "%H:%M:%S").time()
                except ValueError as e:
                    raise RESTException("Invalid time. Must be in ISO 8601 format.")
            else:
                return dateutil.parser.parse(value).time()
        elif  isinstance(prop, ndb.DateProperty):
            if dateutil is None:
                try:
                    return datetime.strptime(value, "%Y-%m-%d").date()
                except ValueError as e:
                    raise RESTException("Invalid date. Must be in ISO 8601 format.")
            else:
                return dateutil.parser.parse(value).date()
        elif isinstance(prop, ndb.DateTimeProperty):
            if dateutil is None:
                try:
                    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
                except ValueError as e:
                    raise RESTException("Invalid datetime. Must be in ISO 8601 format.")
            else:
                return dateutil.parser.parse(value)
        elif isinstance(prop, ndb.GeoPtProperty):
            # Convert from string (formatted as '52.37, 4.88') to GeoPt
            return ndb.GeoPt(value)
        elif isinstance(prop, ndb.StructuredProperty):
            # It's a structured property - the input data is a dict - recursively parse it as well
            return self._build_model_from_data(value, prop._modelclass)
        else:
            # Return as-is (no need for further manipulation)
            return value




def get_rest_class(ndb_model, base_url, **kwd):
    """Returns a RESTHandlerClass with the ndb_model and permissions set according to input"""

    class RESTHandlerClass(BaseRESTHandler, blobstore_handlers.BlobstoreUploadHandler, blobstore_handlers.BlobstoreDownloadHandler):

        model = import_class(ndb_model)
        # Save the base API URL for the model (used for BlobKeyProperty)
        if not hasattr(model, 'RESTMeta'):
            class NewRESTMeta: pass
            model.RESTMeta = NewRESTMeta
        model.RESTMeta.base_url = base_url

        permissions = { 'OPTIONS': PERMISSION_ANYONE }
        permissions.update(kwd.get('permissions', {}))
        allow_http_method_override = kwd.get('allow_http_method_override', True)
        allowed_origin = kwd.get('allowed_origin', None)

        # Wrapping in a list so the functions won't be turned into bound methods
        after_get_callback = [kwd.get('after_get_callback', None)]
        before_post_callback = [kwd.get('before_post_callback', None)]
        after_post_callback = [kwd.get('after_post_callback', None)]
        before_put_callback = [kwd.get('before_put_callback', None)]
        after_put_callback = [kwd.get('after_put_callback', None)]
        before_delete_callback = [kwd.get('before_delete_callback', None)]
        after_delete_callback = [kwd.get('after_delete_callback', None)]

        # Validate arguments (we do this at this stage in order to raise exceptions immediately rather than while the app is running)
        if PERMISSION_OWNER_USER in permissions.values():
            if not hasattr(model, 'RESTMeta') or not hasattr(model.RESTMeta, 'user_owner_property'):
                raise ValueError('Must define a RESTMeta.user_owner_property for the model class %s if user-owner permission is used' % (model))
            if not hasattr(model, model.RESTMeta.user_owner_property):
                raise ValueError('The user_owner_property "%s" (defined in RESTMeta.user_owner_property) does not exist in the given model %s' % (model.RESTMeta.user_owner_property, model))

        def __init__(self, request, response):
            self.initialize(request, response)
            blobstore_handlers.BlobstoreUploadHandler.__init__(self, request, response)
            blobstore_handlers.BlobstoreDownloadHandler.__init__(self, request, response)

            self.after_get_callback = self.after_get_callback[0]
            self.before_post_callback = self.before_post_callback[0]
            self.after_post_callback = self.after_post_callback[0]
            self.before_put_callback = self.before_put_callback[0]
            self.after_put_callback = self.after_put_callback[0]
            self.before_delete_callback = self.before_delete_callback[0]
            self.after_delete_callback = self.after_delete_callback[0]


        def rest_method_wrapper(func):
            """Wraps GET/POST/PUT/DELETE methods and adds standard functionality"""

            def inner_f(self, model_id, property_name=None):
                # See if method type is supported
                method_name = func.func_name.upper()
                if method_name not in self.permissions:
                    return self.method_not_allowed()

                # Verify permissions
                permission = self.permissions[method_name]

                if (permission in [PERMISSION_LOGGED_IN_USER, PERMISSION_OWNER_USER, PERMISSION_ADMIN]) and (not self.user):
                    # User not logged-in as required
                    return self.unauthorized()

                elif permission == PERMISSION_ADMIN and not self.is_user_admin:
                    # User is not an admin
                    return self.permission_denied()

                try:
                    # Call original method
                    if model_id:
                        model = self._model_id_to_model(model_id.lstrip('/')) # Get rid of '/' at the beginning

                        if (permission == PERMISSION_OWNER_USER) and (self.get_model_owner(model) != self.user.key):
                            # The currently logged-in user is not the owner of the model
                            return self.permission_denied()

                        if property_name and model:
                            # Get the original name of the property
                            property_name = translate_property_names({ property_name: True }, model, 'input').keys()[0]

                        result = func(self, model, property_name)
                    else:
                        result = func(self, None, None)

                    if isinstance(result, webapp2.Response):
                        # webapp2.Response instance - no need for further manipulation (return as-is)
                        return result
                    elif not isinstance(result, NoResponseResult):
                        # Only return a result (i.e. write to the response object) if it's not a NoResponseResult (used when serving blobs - BlobKeyProperty)
                        return self.success(result)

                except RESTException, exc:
                    return self.error(exc)

            return inner_f


        #
        # REST endpoint methods
        #



        @rest_method_wrapper
        def options(self, model, property_name=None):
            """OPTIONS endpoint - doesn't return anything (only returns options in the HTTP response headers)"""
            return ''


        @rest_method_wrapper
        def get(self, model, property_name=None):
            """GET endpoint - retrieves a single model instance (by ID) or a list of model instances by query"""

            if not model:
                # Return a query with multiple results

                query = self._filter_query() # Filter the results

                if self.permissions['GET'] == PERMISSION_OWNER_USER:
                    # Return only models owned by currently logged-in user
                    query = query.filter(getattr(self.model, self.user_owner_property) == self.user.key)

                query = self._order_query(query) # Order the results
                (results, cursor) = self._fetch_query(query) # Fetch them (with a limit / specific page, if provided)

                if self.after_get_callback:
                    # Additional processing required
                    results = self.after_get_callback(results)

                return {
                    'results': results,
                    'next_results_url': self._build_next_query_url(cursor)
                    }

            else:

                if property_name:
                    # Return a specific property value - currently supported only for BlobKeyProperty
                    if not hasattr(model, property_name):
                        raise RESTException('Invalid property name "%s"' % property_name)

                    blob_key = getattr(model, property_name)

                    if not blob_key:
                        raise RESTException('"%s" is not set' % property_name)
                    if not isinstance(blob_key, blobstore.BlobKey):
                        raise RESTException('"%s" is not a BlobKeyProperty' % property_name)

                    # Send the blob contents
                    self.send_blob(blob_key)

                    # Make sure we don't return a value (i.e. not write to self.response) - so self.send_blob will work properly
                    return NoResponseResult()


                # Return a single item (query by ID)

                if self.after_get_callback:
                    # Additional processing required
                    model = self.after_get_callback(model)

                return model


        @rest_method_wrapper
        def post(self, model, property_name=None):
            """POST endpoint - adds a new model instance"""

            if model and not property_name:
                # Invalid usage of the endpoint
                raise RESTException('Cannot POST to a specific model ID')

            if model and property_name:
                # POST to a BlobKeyProperty
                if not hasattr(model, property_name):
                    raise RESTException('Invalid property name "%s"' % property_name)
                if not isinstance(model._properties[property_name], ndb.BlobKeyProperty):
                    raise RESTException('"%s" is not a BlobKeyProperty' % property_name)

                # Next, get the created blob
                upload_files = self.get_uploads()

                if not upload_files:
                    # No upload data - this happens when the user POSTS for the first time - we need to create an upload URL and redirect
                    # the user to it (the BlobstoreUploadHandler will handle self.get_uploads() for us and we'll get to the same point).
                    # We do it this way and not simply refer the user directly to create_upload_url, so we won't call create_upload_url
                    # every time the user GETs to /my_model - since each create_upload_url call creates more DB garbage.
                    upload_url = blobstore.create_upload_url(self.request.url)
                    return self.redirect(upload_url, code=307) # We use a 307 redirect in order to tell the client (e.g. browser) to use the same method type (POST) and keep its POST data

                blob_info = upload_files[0]

                if getattr(model, property_name):
                    # The property already has a previous value - delete the older blob
                    blobstore.delete(getattr(model, property_name))

                # Set the blob reference
                setattr(model, property_name, blob_info.key())
                model.put()

                # Everything was OK
                return { 'status': True }



            try:
                # Parse POST data as JSON
                json_data = json.loads(self.request.body)
            except ValueError as exc:
                raise RESTException('Invalid JSON POST data')

            if not isinstance(json_data, list):
                json_data = [json_data]

            models = []

            for model_to_create in json_data:
                try:
                    # Any exceptions raised due to invalid/missing input will be caught
                    model = self._build_model_from_data(model_to_create, self.model)
                    models.append(model)

                except Exception as exc:
                    raise RESTException('Invalid JSON POST data - %s' % exc)

            if self.before_post_callback:
                models = self.before_post_callback(models, json_data)

            # Commit all models in a transaction
            created_keys = ndb.put_multi(models)

            if self.after_post_callback:
                models = self.after_post_callback(created_keys, models)

            # Return the newly-created model instance(s)
            return models


        @rest_method_wrapper
        def put(self, model, property_name=None):
            """PUT endpoint - updates an existing model instance"""
            models = []

            try:
                # Parse PUT data as JSON
                json_data = json.loads(self.request.body)
            except ValueError as exc:
                raise RESTException('Invalid JSON PUT data')

            if model:
                # Update just one model
                model = self._build_model_from_data(json_data, self.model, model)
                json_data = [json_data]
                models.append(model)
            else:
                # Update several models at once

                if not isinstance(json_data, list):
                    raise RESTException('Invalid JSON PUT data')

                for model_to_update in json_data:

                    model_id = model_to_update.pop('id', None)

                    if model_id is None:
                        raise RESTException('Missing "id" argument for model')

                    model = self._model_id_to_model(model_id)
                    model = self._build_model_from_data(model_to_update, self.model, model)
                    models.append(model)

            if self.before_put_callback:
                models = self.before_put_callback(models, json_data)

            # Commit all models in a transaction
            updated_keys = ndb.put_multi(models)

            if self.after_put_callback:
                models = self.after_put_callback(updated_keys, models)

            return models


        def _delete_model_blobs(self, model):
            """Deletes all blobs associated with the model (finds all BlobKeyProperty)"""

            for (name, prop) in model._properties.iteritems():
                if isinstance(prop, ndb.BlobKeyProperty):
                    if getattr(model, name):
                        blobstore.delete(getattr(model, name))



        @rest_method_wrapper
        def delete(self, model, property_name=None):
            """DELETE endpoint - deletes an existing model instance"""
            models = []

            if model:
                models.append(model)
            else:
                # Delete multiple model instances

                if self.permissions['DELETE'] == PERMISSION_OWNER_USER:
                    # Delete all models owned by the currently logged-in user
                    query = self.model.query().filter(getattr(self.model, self.user_owner_property) == self.user.key)
                else:
                    # Delete all models
                    query = self.model.query()

                # Delete the models (we might need to fetch several pages in case of many results)
                cursor = None
                more_available = True

                while more_available:
                    results, cursor, more_available = query.fetch_page(BaseRESTHandler.DEFAULT_MAX_QUERY_RESULTS, start_cursor=cursor)
                    if results:
                        models.extend(results)

            if self.before_delete_callback:
                models = self.before_delete_callback(models)

            for m in models:
                self._delete_model_blobs(m) # No easy way to delete blobstore entries in a transaction

            deleted_keys = ndb.delete_multi(m.key for m in models)

            if self.after_delete_callback:
                self.after_delete_callback(deleted_keys, models)

            # Return the deleted models
            return models

        #
        # Utility methods/properties
        #


        @webapp2.cached_property
        def is_user_admin(self):
            """Determines if the currently logged-in user is an admin or not (relies on the user class RESTMeta.admin_property)"""

            if not hasattr(self.user, 'RESTMeta') or not hasattr(self.user.RESTMeta, 'admin_property'):
                # This is caused due to a misconfiguration by the coder (didn't define a proper RESTMeta.admin_property) - we raise an exception so
                # it'll trigger a 500 internal server error. This specific argument validation is done here instead of the class definition (where the
                # rest of the arguments are being validated) since at that stage we can't see the webapp2 auth configuration to determine the User model.
                raise ValueError('The user model class %s must include a RESTMeta class with `admin_property` defined' % (self.user.__class__))

            admin_property = self.user.RESTMeta.admin_property
            if not hasattr(self.user, admin_property):
                raise ValueError('The user model class %s does not have the property %s as defined in its RESTMeta.admin_property' % (self.user.__class__, admin_property))

            return getattr(self.user, admin_property)

        @webapp2.cached_property
        def user_owner_property(self):
            """Returns the name of the user_owner_property"""
            return self.model.RESTMeta.user_owner_property

        def get_model_owner(self, model):
            """Returns the user owner of the given `model` (relies on RESTMeta.user_owner_property)"""
            return getattr(model, self.user_owner_property)





    # Return the class statically initialized with given input arguments
    return RESTHandlerClass


class RESTHandler(NamePrefixRoute): # We inherit from NamePrefixRoute so the same router can actually return several routes simultaneously (used for BlobKeyProperty)
    """Returns our RequestHandler with the appropriate permissions and model. Should be used as part of the WSGIApplication routing:
            app = webapp2.WSGIApplication([('/mymodel', RESTHandler(
                                                MyModel,
                                                permissions={
                                                    'GET': PERMISSION_ANYONE,
                                                    'POST': PERMISSION_LOGGED_IN_USER,
                                                    'PUT': PERMISSION_OWNER_USER,
                                                    'DELETE': PERMISSION_ADMIN
                                                }
                                           )])
    """

    def __init__(self, url, model, **kwd):

        url = url.rstrip(' /')
        model = import_class(model)

        if not url.startswith('/'):
            raise ValueError('RESHandler url should start with "/": %s' % url)

        routes = [
                # Make sure we catch both URLs: to '/mymodel' and to '/mymodel/123'
                webapp2.Route(url + '<model_id:(/.+)?|/>', get_rest_class(model, url, **kwd), 'main')
            ]


        included_properties = get_included_properties(model, 'input')
        translation_table = get_translation_table(model, 'input')

        # Build extra routes for each BlobKeyProperty
        for (name, prop) in model._properties.iteritems():
            if isinstance(prop, ndb.BlobKeyProperty) and name in included_properties:
                # Register a route for the current BlobKeyProperty

                property_name = translation_table.get(name, name)
                blob_property_url = '%s/<model_id:.+?>/<property_name:%s>' % (url, property_name) # e.g. /api/my_model/<SOME_KEY>/blob_prop

                # Upload/Download blob route and handler
                routes.insert(0, webapp2.Route(blob_property_url, get_rest_class(model, url, **kwd), 'upload-download-blob'))



        super(RESTHandler, self).__init__('rest-handler-', routes)



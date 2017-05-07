Developer notes
===============

Templates are [mustache](https://mustache.github.io/) templates.

Exception mapping
-----------------

in us.kbase.auth2.exceptions  
AuthException and subclasses other than the below - 400  
AuthenticationException and subclasses - 401  
UnauthorizedException and subclasses - 403  
NoDataException and subclasses - 404  

JsonMappingException (from Jackson) - 400  

Anything else is mapped to 500.

# Authentication service environments

The auth service can support multiple environments, allowing it to service multiple hosts.
Alternate environments only affect account login and linking - all the environments share
tokens and are invisible from the perspective of a service contacting the auth server to look up
users or validate tokens.

## Setup

There are several steps to setting up an environment. The following steps assume the the default
or standard environment is `host1.org` and is properly configured in the auth service and
3rd party identity providers (IDPs). The new environment is assumed to be served at `host2.org`.
The environment names, respectively, will be `host1` and `host2`.

* The login and link redirect URLs for `host2` must be registered with each IDP.
  * They are usually going to be the same as the redirect URLs for `host1` with the replacement
    of `host1.org` with `host2.org`. However, if URLs are rewritten by the remote proxy in
    a different manner between `host1` and `host2` that must be taken into account.
* The login and link redirect URLs must be added to the `deploy.cfg` file as described in
  `deploy.cfg.example`. If using the Docker image, they need to be added to the environment
  in the `env1` and `auth_base_url_env1` keys or the `additional_config` key.
  * For example:

```
identity-provider-Google-env-host2-login-redirect-url=https://host2.org/auth/login/complete/google
identity-provider-Google-env-host2-link-redirect-url=https://host2.org/auth/link/complete/google
```

* The new environment must be activated in the `deploy.cfg` file, either directly or via
  environment variable if using Docker:

```
identity-provider-envs=<existing environments>, host2
```

* On login or linking requests, the auth server must know which environment to use. There are two
  options for providing this information:
  * Send a header to the auth server defining the environment. The name of the header is
    defined in the `deploy.cfg` `environment-header` key. For example, if the environment
    header was set to `X-AUTH-ENV` the auth service would receive requests with the header
    `X-AUTH-ENV: host2` in order to set the environment to `host2`. This is the simplest
    and preferred approach, as it generally only needs a one line addition to the reverse
    proxy configuration for the host, at which point all requests to the auth service get the
    environment header.
  * The UI code can specify the environment when contacting the auth2 service to start a login or
    link flow via the `environment` form parameter. This requires the UI code to be
    environment aware which is generally held to be undesired.
* Once the previous steps have been completed the service can be restarted with the updated
  configuration.
* The final step requires an admin to go to the `/admin/config` endpoint of the auth server.
  The new environment should now be visible in the configuration. While the IDP relevant
  configuration is all specified in the `deploy.cfg` file to avoid passing secrets over the API
  and to locate cohesive configuration elements together, the host side configuration is
  updateable on the fly via the API. The redirect URLs for login and linking must be updated
  appropriately for the host. In many cases, this will be simply replacing `host1.org` with
  `host2.org` but see the previously mentioned caveats regarding updating the URLs.

## Notes

* When using multiple environments, it may be wise to clear the default environment and use
  alternate environments for all the environments. This makes it less likely that a
  misconfiguration could cause an alternate environment to use settings from the default
  environment mistakenly.
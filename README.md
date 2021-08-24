# auth-server

A very simple standalone authentication server Express app.

It can be used for protecting web sites with NGINX subrequest authentication.

- Use `auth_request /__auth/auth` in [NGINX conf](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).
- When user requests protected area, NGINX makes an internal request to `/__auth/auth`. If 201 is returned, protected contents are served. Anything else, NGINX responds with 401.
- `/__auth` is reverse proxied to Express app [auth-server](https://github.com/andygock/auth-server) which handles authentication. Cookies are passed on as well, so the auth server can check for a [JWT](https://jwt.io/).
- Auth server sets httpOnly cookie containing a JWT.
- JWT updated with new expiry each time a user visits protected area.

## How to use

Refer to this tutorial on a blog of the original author:

<https://gock.net/blog/2020/nginx-subrequest-authentication-server/>

### Example nginx config

```nginx
server {
    # ...

    location / {
        # Uncomment this if you want to allow hosts without auth
        #satisfy any;
        #allow 192.168.1.0/24;
        #deny all;

        # This is the main directive
        auth_request /__auth/auth;

        # Here you setup the site
        # ...
    }
    location = /__auth/auth {
        internal;
        proxy_pass http://127.0.0.1:3003;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Remote-Addr $remote_addr;
        proxy_set_header X-Original-Host $host;
    }
    location /__auth {
        proxy_pass http://127.0.0.1:3003;
    }
    # redirect to login on 401
    error_page 401 /__auth/login;
}
```

## Configure

- in `.env`:
    - `AUTH_PORT` - listening port of application (default: 3003)
    - `AUTH_TOKEN_SECRET` - secret used for signing the JWT
- in `users.txt`
    - `username:hash` pairs. If second in pair is not hash (those start with $)
      then it automatically converts it to one. Loaded on server start.
    - you can also append `:admin` to specify that user is admin

## Production

Install following systemd service

```systemd
[Unit]
Description=Auth Service

[Service]
ExecStart=/usr/bin/node app.js
User=the-user
WorkingDirectory=/path/to/cloned/repo

[Install]
WantedBy=multi-user.target
```

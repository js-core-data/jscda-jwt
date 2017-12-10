# jscda-jwt

JWT plugin for js-core-data-app

[![Build Status](https://travis-ci.org/js-core-data/jscda-jwt.svg?branch=master)](https://travis-ci.org/js-core-data/jscda-jwt)

# Example

For js-core-data-app middleware

```
module.exports = app => {

    // get JWT payload
    app.use((req, res, next) => {
        app.locals
            .getJWT(req)
            .then(result => {
                res.send(result);
            })
            .catch(next);
    });

    // validate token permissions
    app.use((req, res, next) => {
        app.locals
            .checkJWTPermissions(req, 'resource_name_to_validate')
            .then(result => {
                if (!result) {
                    return res.status(403).send('forbidden')
                }
                next()
            })
            .catch(next);
    });
}
```

## JWT Permissions

To be able to control access, you can simply add `permissions` to JWT payload.
Example content (rule per line):

```
allow|* //allow access to every resource
allow|foo:test:aaa // allow access to secfootion:test:aaa
allow|foo:*:a* // allow access to foo:any:a, foo:any:ab, foo:any:abcdefg...
deny|blah* // deny access to blah, blahany, ...
```

Rules can be combined with presumption of denial.

```
allow|blah*
deny|blah:test*

...
"foo" -> false
"blah" -> true
"blahadfsdf" -> true
"blah:test" -> false
"blah:testadfadf" -> false
```

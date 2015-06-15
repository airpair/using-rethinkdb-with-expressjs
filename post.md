## Using RethinkDB with Express JS

[RethinkDB](http://rethinkdb.com/) is an easy to use JSON database written from the ground up for the realtime web. This article will introduce you to the basics of using it with [Express JS](http://expressjs.com/) to build an API. As an added bonus we’ll also learn about [JSON Web Tokens](http://jwt.io/). A [complete example](https://github.com/cmwalsh/express_rethink) is available on Github if you prefer to just read the code. Actually you should read it anyway so you can see the code in context.

Please make sure you have RethinkDB installed and running on your system by following the instructions in the [official documentation](http://rethinkdb.com/docs/install/) for your operating system. At the time of writing, Windows is not a support platform.

## Starting an Express JS application

To get started writing an Express JS application we first need to install our dependencies from [npm](https://www.npmjs.com/). Generate a `package.json` file by opening a terminal prompt in the applications root directory and type `npm init`. This will ask you a series of questions about the application such as the name, version number and the type of license to use. I usually go with the defaults and edit the file once it has been generated. In the example below I've added `"private": true` so it doesn't accidentally get published to npm and replaced the `"test"` line inside scripts with `"start": "node app.js"`.

~~~ javascript
{
  "name": "express_rethink",
  "version": "0.0.2",
  "description": "An Express JS and RethinkDB example",
  "main": "app.js",
  "private": true,
  "scripts": {
    "start": "node app.js"
  },
  "author": "Craig Walsh",
  "license": "MIT"
}
~~~

Next we install the dependencies. Notice I've used the `--save` argument at the end of the command. This will write the module name and version number to the `package.json` file so in the future, all we need to do is type `npm install` to get the dependencies.

~~~ bash
npm install bcrypt bluebird body-parser cors dotenv express helmet jwt-simple moment morgan rethinkdb --save
~~~

You should now see a new folder called `node_modules` in the applications root directory. This is where all the software we have just installed is kept. It's good practice to ignore this directory in your version control system.

## The main application file

When we type `npm start` to run the application, it's going to look for a file called `app.js` to tell it what to do. Create a file called `app.js` and require the modules needed, then assign an instance of the Express application server to a variable called `app`.

~~~ javascript
var express = require('express');
var logger = require('morgan');
var bodyParser = require('body-parser');
var cors = require('cors');
var helmet = require('helmet');
require('dotenv').load();

var app = express();
~~~

Now we call the `use` method on our application instance to configure the modules we required. Make sure you read the documentation for any module you plan to use with Express JS so you know how it's configured.

~~~ javascript
app.use(logger('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());
app.use(helmet());
~~~

In the last section, there is some error handling code and a server definition so that Express JS knows what port to serve the application on.

~~~ javascript
app.use(function (error, request, response, next) {
    response.status(error.status || 500);
    response.json({ error: error.message });
});

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log('App is listening on http://%s:%s', host, port);
});
~~~

## Express JS routes

The next job is to add endpoints so the user can interact with our API. Create a folder in the root directory called `routes`. Inside, create two files called `users.js` and `login.js`. It's in these files we'll write the applications route definitions but before that, we need to link to them from the `app.js` file.

~~~ javascript
var users = require('./routes/users');
var login = require('./routes/login');

app.use('/users', users);
app.use('/login', login);
~~~

Assign the files we created to a variable and then call `use` again on the `app` instance, passing in a URL and the assigned variable. The URL will be what the user types into the address bar in the browser to gain access to the routes in that file.

Now to define the routes themselves. Start by requiring `express` and assigning an instance of the `express.Router()` to a variable. We can call `get`, `post`, `put` and `delete` (to name the popular ones) on the router instance to define routes. Here I'm calling `get` to write "Hello World" to the screen.

~~~ javascript
var express = require('express');
var router = express.Router();

router.get('/', function (request, response) {
    response.send("Hello World!");
});
~~~

To learn more about routing in Express JS, take a look the the [official documentation](http://expressjs.com/starter/basic-routing.html).

## Configuring RethinkDB

To configure RethinkDB, the first thing we need to do is create the database and users table. This can be automated with scripts but I’m going to show you how to do it using the RethinkDB Administration Console.

Open a browser and navigate to `http://localhost:8080`. Click on the `Tables` section at the top. You should see the test database listed. Click on the `Add Database` button and follow the on screen instructions to create a database named `express_rethink`. Now click on the `Add Table` button and follow the same procedure to create a table called `users`.

To enable the application to interact with the database, we need to supply some information about where to find the database server, what port it’s running on and the name of the database we’re working with. Create a file called `database.js` in the `config` directory.

~~~ javascript
module.exports = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    db: process.env.DB_NAME
};
~~~

We’re using environment variables to store database information because it’s not a good idea to have it available for everyone to see (more on this later). Using the `dotenv` module we installed earlier, we can read this information from a file called `.env` in the root directory.

~~~
DB_HOST=localhost
DB_PORT=28015
DB_NAME=express_example
~~~

## ReQL query library

To make the code more readable we’ll put everything needed to run queries against the database in a separate file. This way we can just drop the file into other projects using RethinkDB and only have to maintain one codebase.

Using [Rethink’s query language](http://rethinkdb.com/docs/introduction-to-reql/) (ReQL) we can make function calls using Javascript to get information out of the database. The queries are chainable, so it’s not unlike writing Node code, and executed on the server once you call `run` and pass in an active connection.

Create a file in the `lib` directory called `rethink.js`. Require the `rethink` module and the configuration information we wrote in the previous section, then use `rdb.connect` to open a connection to the database. Inside that block, write a function called `find` that passes in a table name and id. We’ll use this information to build the query, run it on the server and the return the result to the calling function.

~~~ javascript
var rdb = require('rethinkdb');
var dbConfig = require('../config/database');

var connection = rdb.connect(dbConfig)
.then(function (connection) {

    module.exports.find = function (tableName, id) {
        return rdb.table(tableName).get(id).run(connection)
        .then(function (result) {
            return result;
        });
    };

});
~~~

Take a look at the other queries I’ve included in the [Github example](https://github.com/cmwalsh/express_rethink/blob/master/lib/rethink.js) to perform common CRUD operations. Notice that when the query finds more than one result it returns a cursor which much be converted to an array so it can be parsed. A great place to find common tasks and queries is in the [Cookbook](http://rethinkdb.com/docs/cookbook/javascript/) section on Rethink’s official documentation.

## Authenticating users

In order to Authenticate users we need to store details about their name, email address and password. It’s our job to be responsible about what we do with the information entrusted to us, so we will only store an encrypted version of their password.

The first thing we need to do is write the function that will encrypt the users password. Before we do though, there is an interesting problem that needs some further explanation.

If you use the code found in the [`bcrypt` documentation](https://www.npmjs.com/package/bcrypt) to encrypt the password, the return value will not be what you expect it to be. Because we have separated our database code out into a file of it’s own we need to return the hashed password instead of saving it there and then, but the `save` function will have completed before the `hash_password` function has a chance to return a value.

The solution is to wrap the function in a promise. If you haven’t come across promises yet I highly recommend reading this [HTML5 Rocks article](http://www.html5rocks.com/en/tutorials/es6/promises/). Basically, when the `save` function calls the `hash_password` function, `hash_password` promises to return a value and `save` waits for the promise to be resolved.

Create a file in the `lib` directory called `auth.js` and require the `bcrypt` module. We will also require the `bluebird` module because promises aren’t available in all browsers yet. Write the `hash_password` function passing in the submitted password and fill it in with our promisified bcrypt code.

~~~ javascript
var bcrypt = require('bcrypt');
var Promise = require('bluebird');

module.exports.hash_password = function (password) {
    return new Promise(function (resolve, reject) {
        bcrypt.genSalt(10, function (error, salt) {
            if(error) return reject(error);

            bcrypt.hash(password, salt, function (error, hash) {
                if(error) return reject(error);
                return resolve(hash);
            });
        });
    });
};
~~~

We also need an `authenticate` function that passes in the submitted password and the hash stored in the database for comparison. The bcrypt section is again promisified.

~~~ javascript
module.exports.authenticate = function (password, hash) {
    return new Promise(function (resolve, reject) {
        bcrypt.compare(password, hash, function (error, response) {
            if(error) return reject(error);
            return resolve(response);
        });
    });
};
~~~

## Authorising users

To secure the API further we are using [JSON Web Tokens](http://jwt.io/). This means that when a user successfully authenticates, they are issued a token which must be attached to the headers of every request to a protected route. If the token is not found, or is invalid, access is denied. For a more in depth explanation take a look at this [Smashing Magazine article](http://www.sitepoint.com/using-json-web-tokens-node-js/).

Create a file in the `lib` directory called `token.js`. Require the `jwt-simple` module and `moment` library. We also need to have a secret string that the `jwt-simple` module will use to generate a unique token.

~~~ javascript
var jwt = require('jwt-simple');
var moment = require('moment');
var secret = process.env.TOKEN_SECRET;
~~~

Just like the database information, this should not be available for everyone to see, so add it to the `.env` file we created earlier.

~~~
TOKEN_SECRET=mysupersecretstring
~~~

Write a function called `generate` that passes in the authenticated user. With the `moment` module, we create a date at some point in the future (I've used 7 days but you can use any length of time you want) that will get encoded into the token so that it expires after the given number of days. Using the expiry date, the users email address and the secret string the `encode` method generates a token that is returned to the calling function.

~~~ javascript
module.exports.generate = function (user) {
    var expires = moment().add(7, 'days').valueOf();
    return jwt.encode({ iss: user.email, exp: expires }, secret);
};
~~~

When the client application submits the token with a request, we need to verify that it is valid and has not expired. To do this, write a function called `verify` that passes in the submitted token. If the token does not exist or is not valid an error is generated, otherwise the request is allowed to continue.

~~~ javascript
module.exports.verify = function (token, next) {
    if(!token) {
        var notFoundError = new Error('Token not found');
        notFoundError.status = 404;
        return next(notFoundError);
    }

    if(jwt.decode(token, secret) <= moment().format('x')) {
        var expiredError = new Error('Token has expired');
        expiredError.status = 401;
        return next(expiredError);
    }
};
~~~

Now that we have a way to generate and verify tokens, let’s write the middleware that will authorise the routes we want to protect. For this we need to require the token library we wrote in the last section then simply grab the token from the headers, verify that it’s valid and move on to the next middleware in the stack.

~~~ javascript
var token = require('./token');

module.exports.authorize = function (request, response, next) {
    var apiToken = request.headers['x-api-token'];
    token.verify(apiToken, next);
    next();
};
~~~

The final step in this section is to choose which routes we want to protect. After requiring the `auth.js` library, call the `authorize` function in between the route path and callback. This causes the `authorize` function to run before processing the rest of the route.

~~~ javascript
var auth = require('../lib/auth');

router.get('/', auth.authorize, function (request, response) {
    rdb.findAll('users')
    .then(function (users) {
        response.json(users);
    });
});
~~~

## Receiving login details

Earlier we created an endpoint where users could post their login details. The email address is used to find the user in the database. If no user is found, an error is generated and the request ends. If the user is found, the submitted password and the hashed password from the user record are passed to the `authenticate` method for comparison. If authentication is successful the user is returned a `currentUser` object containing some general information about the user and their access token.

~~~ javascript
var express = require('express');
var rdb = require('../lib/rethink');
var auth = require('../lib/auth');
var token = require('../lib/token');

var router = express.Router();

router.post('/', function (request, response, next) {
    rdb.findBy('users', 'email', request.body.email)
    .then(function (user) {
        user = user[0];

        if(!user) {
            var userNotFoundError = new Error('User not found');
            userNotFoundError.status = 404;
            return next(userNotFoundError);
        }

        auth.authenticate(request.body.password, user.password)
        .then(function (authenticated) {
            if(authenticated) {
                var currentUser = {
                    name: user.name,
                    email: user.email,
                    token: token.generate(user)
                };

                response.json(currentUser);
            } else {
                var authenticationFailedError = new Error('Authentication failed');
                authenticationFailedError.status = 401;
                return next(authenticationFailedError);
            }
        });
    });
});
~~~

## Security considerations

When writing any application for the Internet, security needs to be a major consideration. Email addresses and passwords will by flying around in plain text so it's important to make sure an API like the one we've just been discussing is served over an HTTPS connection. You also need to ensure there is no sensitive data stored in the source code you have published. It's good practice to store information such as secret strings and API keys in environment variables. Oh, and try not to use the same secret string for every application!

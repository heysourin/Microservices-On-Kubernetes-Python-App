import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__) # creating a server
mysql = MySQL(server) # creating mysql object

# config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = int(os.environ.get("MYSQL_PORT"))


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization #? this line retrieves the Authorization header from the incoming request. contains username and password
    if not auth: 
        return "missing credentials", 401

    # check db for username and password
    cur = mysql.connection.cursor() #?Creates a new cursor object, which is used to execute SQL queries.

    #? Executes SQL query: retrieves email and password from db
    res = cur.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    #? checks sql query returned any result
    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]
        
        if auth.username != email or auth.password != password: #? matching user data with db data
            return "invalid credentials", 401
        else: #? user data and db data matched, return JWT
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
    else:
        return "invalide credentials, User does not exist", 401


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
    except:
        return "not authorized", 403

    return decoded, 200


def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)


#? ------------------------- LAST 2 LINES ---------------------------------
#? The if __name__ == "__main__": check ensures that the code inside the if block is only executed when the script is run directly, and not when it is imported as a module.

#? server.run(host="0.0.0.0", port=5000) - This line starts the Flask web server. The host argument is set to "0.0.0.0", which means the server will listen on all public IPs. The port argument is set to 5000, which means the server will listen on port 5000.
#! If we dont set it 0.0.0.0, the default is going to be localhost, means that our api wouldnot be available externally. We are telling our container app to listen to all our docker container IPs(including localhost)
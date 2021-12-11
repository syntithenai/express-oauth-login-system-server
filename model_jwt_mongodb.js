const _ = require('lodash');
const {ObjectId} = require('mongodb');
var JWT = require('jsonwebtoken');

function getModel(db,config) {
    var {sanitizeUser, requestToken, generateToken, loginSuccessJson, requestRefreshToken} = require('./userHelpers')(config)
    var JWT_ISSUER = config.jwtIssuer ? config.jwtIssuer : 'thisdemo';
    var JWT_SECRET_FOR_ACCESS_TOKEN = config.jwtAccessTokenSecret ? config.jwtAccessTokenSecret : 'thisdemosecret';
    var JWT_SECRET_FOR_REFRESH_TOKEN = config.jwtRefreshTokenSecret ? config.jwtRefreshTokenSecret : 'thisdemosecretother';

    // the expiry times should be consistent between the oauth2-server settings
    // and the JWT settings (not essential, but makes sense)
    const JWT_ACCESS_TOKEN_EXPIRY_SECONDS = config.jwtAccessTokenExpirySeconds ? config.jwtAccessTokenExpirySeconds : 1800;             // 30 minutes
    const JWT_REFRESH_TOKEN_EXPIRY_SECONDS = config.jwtRefreshTokenExpirySeconds ? config.jwtRefreshTokenExpirySeconds : 1209600;         // 14 days
    
    const User = db.User;
    const OAuthClient = db.OAuthClient;
    const OAuthAccessToken = db.OAuthAccessToken;
    const OAuthAuthorizationCode = db.OAuthAuthorizationCode;
    const OAuthRefreshToken = db.OAuthRefreshToken;
    
    function generateAccessToken(client, user, scope,callback) {
		//console.log(['generateAccessToken',client, user, scope])
        return new Promise(function(resolve,reject) {
            var token;
            var secret;
            var exp = new Date();
            var payload = {
            // public claims
            iss: JWT_ISSUER,   // issuer
            // private claims
            userId: user._id,
            clientId: client._id,
            client: client,
            user: sanitizeUser(user)
            };
            if (user.is_admin) payload.user.is_admin = true
			
            var options = {
                algorithm: 'HS256'  // HMAC using SHA-256 hash algorithm
            };
            secret = JWT_SECRET_FOR_ACCESS_TOKEN;
            exp.setSeconds(exp.getSeconds() + JWT_ACCESS_TOKEN_EXPIRY_SECONDS);
            payload.exp = exp.getTime();
            token = JWT.sign(payload, secret, options);
            if (callback && typeof callback === "function") {
                callback(false, token);
            }
            resolve(token)
        })
    }


    function getAccessToken(bearerToken, callback) {
		//console.log(['get access token',bearerToken])
        return JWT.verify(bearerToken, JWT_SECRET_FOR_ACCESS_TOKEN, function(err, decoded) {
            if (err) {
              return callback(err, false);   // the err contains JWT error data
            }
            // other verifications could be performed here
            // eg. that the jti is valid

            // we could pass the payload straight out we use an object with the
            // mandatory keys expected by oauth2-server, plus any other private
            // claims that are useful
            return callback(false, {
                accessToken: bearerToken,
                accessTokenExpiresAt: new Date(decoded.exp * 1000),
                scope: decoded.scope,
                user: decoded.user,
                client: decoded.client
            })
                    
        });
    };


    function getClient(clientId, clientSecret) {
		//console.log(['get client',clientId, clientSecret])
      return new Promise(function(resolve,reject) {
          const query = { clientId };
          if (clientSecret) {
            query.clientSecret = clientSecret;
          }
          return OAuthClient
            .findOne(query)
            .lean()
            .then(function(client) {
                return client;
            })
            .then(client => {
                const res = client ? Object.assign(client, { id: clientId }) : null
                resolve(res)
            })
            .catch((err) => {
              console.log('getClient - Err: ', err);
            });
        })
    }

    function getClientById(id) {
		//console.log(['get client by id',id])
      return new Promise(function(resolve,reject) {
          const query = { _id:ObjectId(id)};
          
          return OAuthClient
            .findOne(query)
            .lean()
            .then(function(client) {
                return client;
            })
            .then(client => {
                resolve(client)
            })
            .catch((err) => {
              console.log('getClient - Err: ', err);
            });
        })
    }

    function getUser(username, password) {
		//console.log(['get user',username,password])
      return User
        .findOne({ username, password })
        .lean()
        .then(user => {
            return user
        })
        .catch((err) => {
          console.log('getUser - Err: ', err);
        });
    }

    function getUserById(id) {
		//console.log(['get user by id',id])
      return User
        .findOne({ _id: ObjectId(id) })
        .lean()
        .then(user => user)
        .catch((err) => {
          console.log('getUser - Err: ', err);
        });
    }

    function revokeAuthorizationCode(code) {
      return OAuthAuthorizationCode.findOneAndRemove({ code: code.code })
        .then(removed => !!removed)
        .catch((err) => {
          console.log('revokeAuthorizationCode - Err: ', err);
        });
    }

    function revokeToken(token) {
      return OAuthRefreshToken.findOneAndRemove({ refreshToken: token.refreshToken })
        .then(removed => !!removed)
        .catch((err) => {
          console.log('revokeToken - Err: ', err);
        });
    }


    function saveToken(token, client, user) {
		//console.log(['save token',token,client,user])
      return Promise.all([
        
        token.refreshToken ? OAuthRefreshToken.create({ // no refresh token for client_credentials
          refreshToken: token.refreshToken,
          refreshTokenExpiresAt: token.refreshTokenExpiresAt,
          client: client._id,
          user: user._id,
          scope: token.scope
        }) : Promise.resolve()
      ])
        .then(() => {
            return _.assign({ client, user }, token)
        })
        .catch((err) => {
          console.log('revokeToken - Err: ', err);
        });
    }

    function getAuthorizationCode(code) {
      return OAuthAuthorizationCode
        .findOne({ code })
        .populate('user')
        .populate('client')
        .lean()
        .then((authCodeModel) => {
          if (!authCodeModel) {
            return false;
          }
          const extendedClient = Object.assign(authCodeModel.client, { id: authCodeModel.client.clientId });
          return Object.assign(authCodeModel, { client: extendedClient });
        })
        .catch((err) => {
          console.log('getAuthorizationCode - Err: ', err);
        });
    }

    function saveAuthorizationCode(code, client, user) {
      return OAuthAuthorizationCode
        .create({
          expiresAt: code.expiresAt,
          client: client._id,
          code: code.authorizationCode,
          user: user._id,
          scope: code.scope
        })
        .then(() => ({ // TODO: Consider changing expiresAt to expiresIn (seconds)
          authorizationCode: code.authorizationCode,
          authorization_code: code.authorizationCode,
          expires_in: Math.floor((code.expiresAt - new Date()) / 1000)
        }))
        .catch((err) => {
          console.log('saveAuthorizationCode - Err: ', err);
        });
    }

    function getUserFromClient(client) {
      return User.findById(client.user)
        .lean()
        .then(dbUser => dbUser)
        .catch((err) => {
          console.log('getUserFromClient - Err: ', err);
        });
    }

    function getUserFromAccessToken(bearerToken) {
       return new Promise(function(resolve,reject) {
            return JWT.verify(bearerToken, JWT_SECRET_FOR_ACCESS_TOKEN, function(err, decoded) {
                if (err) {
                  resolve(err, false);   // the err contains JWT error data
                }
                // other verifications could be performed here
                // eg. that the jti is valid

                // we could pass the payload straight out we use an object with the
                // mandatory keys expected by oauth2-server, plus any other private
                // claims that are useful
                resolve(false,decoded.user)
            });
       })
    }

    
    function getRefreshToken(refreshToken) {
      return OAuthRefreshToken
        .findOne({ refreshToken })
        .populate('user')
        .populate('client')
        .lean()
        .then((dbToken) => {
          if (!dbToken) {
            return false;
          }

          const extendedClient = Object.assign(dbToken.client, { id: dbToken.client.clientId });
          return Object.assign(dbToken, { client: extendedClient });
        })
        .catch((err) => {
          console.log('getRefreshToken - Err: ', err);
        });
    }

    /**
    In case there is a need to scopes for the user, uncomment the code.
    It will also be required to provide scopes for both user and client
    */
    // eslint-disable-next-line
    function validateScope(user, client, scope) {
      //console.log('validateScope', user, client, scope);
      // return (user.scope === scope && client.scope === scope && scope !== null) ? scope: false;
      return '*';
    }

    /**
    In case there is a need to scopes for the user, uncomment the code.
    It will also be required to provide scopes for both user and client (They should also match)
    */
    // eslint-disable-next-line
    function verifyScope(token, scope) {
      // console.log('verifyScope', token, scope);
      // return token.scope === scope;
      return true;
    }


    function findOrCreateUser(name,email,cb) {
      if (email && email.length > 0) {
        // if (!config.allowedUsers || config.allowedUsers.length === 0 ||  (config.allowedUsers.indexOf(email.toLowerCase().trim()) >= 0 )) {
          db.User.findOne({username:email.trim()}).then(function(user) {
              if (user!=null) {
                  // USER LOGIN SUCCESS JSON
                cb(null,user.toObject());
              } else {
                var pw = crypto.randomBytes(20).toString('hex');
                let item={name:name,username:email,password:pw};
                            if (config.encryptedPasswords) {
                                item.password = md5(pw)
                            }
                 if (!item.avatar) item.avatar = faker.commerce.productAdjective()+faker.name.firstName()+faker.name.lastName()
                
                let user = new database.User(item);
                user.save().then(function() {;
                  // USER LOGIN SUCCESS JSON
                  cb(null,user.toObject());
                });
              }
           }).catch(function(e) {
             cb(e, null);
           });
        // } else {
        //   cb('Not allowed to register', null);
        // }		 
      } else {
        cb('no user', null);
      }
    }
  
    function findUserByUsername(username, password=null) {
      return new Promise(function(resolve,reject) {
        db.User.findOne({ username: username }, function (err, user) {
          // if (err) { resolve(err); }
          // console.log('findUserByUsername', username, err, user);
          if (!user) {
            resolve(null) // { message: 'Incorrect login details' },null);
          }
          // console.log('findUserByUsername check pw', password, user);
          // check password if supplied
          if (password && password.length > 0) {
            if (user.password !== password) { 
              resolve(null) //{ message: 'Incorrect login details' }),null;
            }
          }
          resolve(user);
        })
      })
    }

    function findUserByAvatar(avatar) {
      return new Promise(function(resolve,reject) {
        db.User.findOne({ avatar: avatar }, function (err, user) {
          resolve(user);
        })
      })
    }

    function findUserBySignupToken(token) {
      return new Promise(function(resolve,reject) {
        db.User.findOne({ signup_token: token }, function (err, user) {
          resolve(user);
        })
      })
    } 

    function findUserByRecoveryToken(token) {
      return new Promise(function(resolve,reject) {
        db.User.findOne({ recover_password_token: token }, function (err, user) {
          resolve(user);
        })
      })
    }

    function saveUser(saveuser) {
      return new Promise(function(resolve,reject) {
        if (saveuser && saveuser.username) {
          db.User.updateOne({username:saveuser.username},saveuser,{upsert:true},function(err,user) {
            if (err) {
              reject(err);
            } else {
              resolve(user);
            }
          });
        } else {
          reject()
        }
      })
    }

    function createClients(clients) {
      return new Promise(function(resolve,reject) {
        var promises = []
        if (Array.isArray(clients)) {
          clients.forEach(function(clientConfig) {
            //console.log(['CREATE AUTH CLIENT',clientConfig.clientId])
            db.OAuthClient.findOne({clientId: clientConfig.clientId}).then(function(result) {
              let clientFields = 	{
                clientId: clientConfig.clientId, 
                clientSecret:clientConfig.clientSecret,
                clientName:clientConfig.clientName,
                clientBy:clientConfig.clientBy,
                website_url:clientConfig.clientWebsite,
                redirectUris:clientConfig.redirectUris,
                clientImage:clientConfig.clientImage
              };
              //console.log(clientFields)
              if (result!= null) {
                // OK
                //console.log('CREATE push update');
                promises.push(db.OAuthClient.update({clientId:clientConfig.clientId},clientFields))
              } else {
                //console.log('CREATE push save');
                let client = new db.OAuthClient(clientFields);
                promises.push(client.save())
              }
              Promise.all(promises).then(function(res) {
                //console.log(['CREATED AUTH CLIENTS',res])
                db.OAuthClient.find({}).then(function(foundClients) {
                  //console.log(['CREATED AUTH CLIENTS found',foundClients])
                  resolve()
                })
              })
            }).catch(function(e) {
              //console.log('CREATE AUTH ERR');
              console.log(e);
              resolve()
            }) 
          })
        } else {
          resolve()
        }
        
      })
    }

    function deleteRefreshTokensForUser(userId) {
      return db.OAuthRefreshToken.deleteMany({user:ObjectId(userId)})
    }

    return {
       generateAccessToken, 
       getAccessToken,
      getAuthorizationCode,
      getClient,
      getRefreshToken,
      getUser,
      getUserFromClient,
      revokeAuthorizationCode,
      revokeToken,
      saveToken,
      saveAuthorizationCode,
      validateScope,
      verifyScope,
      getUserFromAccessToken,
      findOrCreateUser,
      findUserByUsername,
      findUserBySignupToken,
      findUserByRecoveryToken,
      findUserByAvatar,
      saveUser,
      deleteRefreshTokensForUser,
      createClients
    };
}


module.exports = getModel

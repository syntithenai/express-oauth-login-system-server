var fetch = require('node-fetch');


function getUserHelpers(config) {

// CALLBACK WHEN USER IS IDENTIFIED TO ADD TOKEN AND SET refresh COOKIE
            function loginSuccessJson(user,res,cb) {
                //console.log(['SAVE USER',user]);
                requestToken(user).then(function(userAndToken) {
                        let token = userAndToken.token;
                        if (token) {
                            console.log(['RTA',token.refresh_token])
                            res.cookie('refresh_token',token.refresh_token,{httpOnly: true, maxAge: 604800000})
                            cb(null,Object.assign(sanitizeUser(userAndToken),{token:token}))
                        } else {
                            cb('missing token on login success',null)
                        }
                  });
            }

            function generateToken() {	
                return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            }
            
            // MAKE A USER/PASS REQUEST FOR A TOKEN AND RESOLVE THE EXTENDED USER 
            function requestToken(user) {
                 return new Promise(function(resolve,reject) {
                     var params={
                        username: user.username,
                        password: user.password,
                        'grant_type':'password',
                        'client_id':config.clientId,
                        'client_secret':config.clientSecret,
                    };
                      console.log(['RQUEST TOKEN',params])
                      return fetch(config.authServer+"/token", {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                          },
                          
                          body: Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&')
                        }).then(function(response) {
                            return response.json();
                        }).then(function(token) {
                            console.log(['req got token',token])
                            if (token && token.access_token && token.access_token.length > 0) {
                                user.token = token;
                                resolve(user);
                            } else {
                                console.log(['ERROR REQUESTING TOKEN',token])
                            }
                            reject();
                        }).catch(function(err) {
                                console.log(['ERROR REQUESTING TOKEN',err])
                                reject();
                        });
                });
            }

            // MAKE OAUTH REFRESH REQUEST
            function requestRefreshToken(refreshToken) {
                 return new Promise(function(resolve,reject) {
                     var params={
                        refresh_token: refreshToken,
                        'grant_type':'refresh_token',
                        'client_id':config.clientId,
                        'client_secret':config.clientSecret
                      };
                    //  console.log(['RQUEST TOKEN',params])
                      return fetch(config.authServer+"/token", {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                          },
                          
                          body: Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&')
                        }).then(function(response) {
                            return response.json();
                        }).then(function(token) {
                            if (token.access_token && token.access_token.length > 0) {
                                resolve(token);
                            } else {
                                console.log(['ERROR REQUESTING TOKEN',token])
                                reject(token);
                            }
                        }).catch(function(err) {
                                console.log(['ERROR REQUESTING TOKEN',err])
                        });
                });
            }
                        
            
            // SANITIZE USER TO BE DELIVERED TO THE CLIENT, ONLY ALLOWED FIELDS FROM config.userFields and no password fields
            function sanitizeUser(user) {
                let item={};
                if (!config.userFields || config.userFields.length === 0) config.userFields=['name','avatar','username','token','password','tmp_password']

                config.userFields.map(function(fieldName) {
                    let key = fieldName.trim();
                    item[key] = typeof user[key] ==="string" ? user[key].trim() : '';
                 });
                 if (user._id) item._id = user._id;
                 delete item.password;
                 delete item.tmp_password;
                 return item;
            }
        
            return {sanitizeUser, requestToken, requestRefreshToken, generateToken, loginSuccessJson}
        }
        
module.exports = getUserHelpers

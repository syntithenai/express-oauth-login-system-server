var fetch = require('node-fetch');
var md5 = require('md5')
const database = require('./database');

function getUserHelpers(config) {

// CALLBACK WHEN USER IS IDENTIFIED TO ADD TOKEN AND SET refresh COOKIE
            function loginSuccessJson(user,res,cb) {
				console.log('USER HELPERS loginSuccessJson')
				console.log(user)
				
				function doRequestToken(user) {
					requestToken(user).then(function(userAndToken) {
							let token = userAndToken && userAndToken.token ? userAndToken.token : null;
							if (token) {
								res.cookie('refresh_token',token.refresh_token,{httpOnly: true, maxAge: 604800000, secure: true, sameSite: 'None'})
								res.cookie('media_token',md5(token.refresh_token),{maxAge: 604800000, secure: true, sameSite: 'None'});
								cb(null,Object.assign(sanitizeUser(userAndToken),{token:token}))
							} else {
								cb('missing token on login success',null)
							}
					  });
				}
				if (user && user.password && user.password.length > 0) {
					doRequestToken(user)
				// user registered but not confirmed , 
				} else if (user && user._id && new String(user._id).length > 0) {
					console.log('do search')
					database.User.findOne(user._id).then(function(user) {
						console.log('searcj res')
						console.log(user)
						if (user) {
							user.password = user && user.tmp_password && user.tmp_password.length > 0 ? user.tmp_password : (Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15));
							user.save().then(function(res2) {
								console.log('saved')
								console.log(res2)
								doRequestToken(user)
							})
						} else {
							console.log('no user')
						}
					})
				}
				
            }

            function generateToken() {	
                return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            }
            
            // MAKE A USER/PASS REQUEST FOR A TOKEN AND RESOLVE THE EXTENDED USER 
            function requestToken(user) {
				console.log('USER HELPER REQUEST TOKEN')
                 return new Promise(function(resolve,reject) {
					 try {
						 var params={
							username: user.username,
							password: user.password,
							'grant_type':'password',
							'client_id':config.clientId,
							'client_secret':config.clientSecret,
						  };
						  return fetch( config.authServer+"/token", {
							  method: 'POST',
							  headers: {
								'Content-Type': 'application/x-www-form-urlencoded',
							  },
							  
							  body: Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&')
							}).then(function(response) {
								return response.json();
							}).then(function(token) {
								if (token && token.access_token && token.access_token.length > 0) {
									user.token = token;
									resolve(user);
								} else {
									console.log(['ERROR REQUESTING TOKEN',token])
								}
								resolve();
							}).catch(function(err) {
									console.log(['ERROR REQUESTING TOKEN',err])
									resolve();
							});
						} catch (e) {
							console.log(['USER HELPER REQUEST TOKEN ERR',e.toString()])
						}
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
                                resolve(token);
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

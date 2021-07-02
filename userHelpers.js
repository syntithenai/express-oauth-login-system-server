var fetch = require('node-fetch');
var https = require('https');
var md5 = require('md5')
const database = require('./database');

function getUserHelpers(config) {


// CALLBACK WHEN USER IS IDENTIFIED TO ADD TOKEN AND SET refresh COOKIE
            function loginSuccessJson(user,res,cb) {
				
				function doRequestToken(user) {
					//console.log('DO REQUEST TOKEN')
					requestToken(user).then(function(userAndToken) {
						//console.log(['DONE REQUEST TOKEN',userAndToken])
							let token = userAndToken && userAndToken.token ? userAndToken.token : null;
							if (token) {
								//console.log(['DONE REQUEST TOKEN set refresh cookie',token.refresh_token])
								res.cookie('refresh_token',token.refresh_token,{httpOnly: true, maxAge: config.jwtRefreshTokenExpirySeconds, secure: true, sameSite: 'None'})
								res.cookie('media_token',md5(token.refresh_token),{maxAge: config.jwtRefreshTokenExpirySeconds, secure: true, sameSite: 'None'});
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
					database.User.findOne(user._id).then(function(user) {
						if (user) {
							user.password = user && user.tmp_password && user.tmp_password.length > 0 ? user.tmp_password : (Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15));
							user.save().then(function(res2) {
								doRequestToken(user)
							})
						} 
						//else {
							//console.log('no user')
						//}
					})
				}
				
            }

            function generateToken() {	
                return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            }
            
            // MAKE A USER/PASS REQUEST FOR A TOKEN AND RESOLVE THE EXTENDED USER 
            function requestToken(user) {
				 return new Promise(function(resolve,reject) {
					 try {
						 var params={
							username: decodeURIComponent(user.username),
							password: decodeURIComponent(user.password),
							'grant_type':'password',
							'client_id':config.clientId,
							'client_secret':config.clientSecret,
							
						  };
						  //console.log(params)
						  //console.log(config.authServer)
						  return fetch( config.authServer+"/token", {
							  method: 'POST',
							  headers: {
								'Content-Type': 'application/x-www-form-urlencoded',
							  },
							  agent: new https.Agent({  
								rejectUnauthorized: false
							  }),
							  body: Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&')
							}).then(function(response) {
								//console.log(response)
								return response.json();
							}).then(function(token) {
								//console.log(token)
								
								if (token && token.access_token && token.access_token.length > 0) {
									user.token = token;
									resolve(user);
								} else {
									console.log(['ERROR REQUESTING TOKEN empty',token])
									resolve();
								}
								
							}).catch(function(err) {
									console.log(['ERROR REQUESTING TOKEN err',err])
									resolve();
							});
						} catch (e) {
							console.log(['USER HELPER REQUEST TOKEN ERR',e.toString()])
							resolve();
						}
                });
            }

            // MAKE OAUTH REFRESH REQUEST
            function requestRefreshToken(refreshToken) {
				//console.log(['rrT',refreshToken])
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
   						  agent: new https.Agent({  
 							rejectUnauthorized: false
						  }),

                          body: Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&')
                        }).then(function(response) {
                            return response.json();
                        }).then(function(token) {
                            if (token.access_token && token.access_token.length > 0) {
                                resolve(token);
                            } else {
                                //console.log(['ERROR REQUESTING TOKEN',token])
                                resolve(token);
                            }
                        }).catch(function(err) {
                                //console.log(['ERROR REQUESTING TOKEN',err])
                                resolve({})
                        });
                });
            }
                        
     
            
            // SANITIZE USER TO BE DELIVERED TO THE CLIENT, ONLY ALLOWED FIELDS FROM config.userFields and no password fields
            //,'password','tmp_password' 
            function sanitizeUser(user) {
                let item={};
                if (!config.userFields || config.userFields.length === 0) config.userFields=['name','avatar','username']

                config.userFields.map(function(fieldName) {
                    let key = fieldName.trim();
                    item[key] = typeof user[key] ==="string" ? user[key].trim() : '';
                 });
                 if (user._id) item._id = user._id;
                 delete item.password;
                 delete item.tmp_password;
                 return item;
            }
        
			function validatePassword(password) {
				var restrictions = config && config.passwordRestrictions && config.passwordRestrictions >= 0 && config.passwordRestrictions <= 3 ?  config.passwordRestrictions : 0
				var hasNumber =  /\d/.test( password)
				var hasPunctuation = /\p{Punct}/.test( password)
				switch(restrictions) {
					case 0:
						return {valid: true}
					case 1:
						if (password.trim().length > 5) {
							return {valid: true}
						} else {
							return {valid: false, message: 'Password must be at least six letters'}
						}
					case 2:
						if (!hasNumber) {
							return {valid: false, message: 'Password must include at least one number'}
						} else if (password.trim().length >7) {
							return {valid: true}
						} else {
							return {valid: false, message: 'Password must have at least eight letters'}
						}
					case 3:
						if (!hasNumber) {
							return {valid: false, message: 'Password must include at least one number'}
						} else if (!hasPunctuation) {
							return {valid: false, message: 'Password must include at least one number'}
						} else if (password.trim().length >7) {
							return {valid: true}
						} else {
							return {valid: false, message: 'Password must be at least eight letters'}
						}
				}
				
			}
        
        
            return {sanitizeUser, requestToken, requestRefreshToken, generateToken, loginSuccessJson, validatePassword}
        }
        
module.exports = getUserHelpers

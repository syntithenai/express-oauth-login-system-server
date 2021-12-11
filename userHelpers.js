//var fetch = require('node-fetch');
var axios = require('axios')
var https = require('https');
var md5 = require('md5')
// const database = require('./mongodb_database');

function isAlphaNumeric(str) {
  var code, i, len;

  for (i = 0, len = str.length; i < len; i++) {
    code = str.charCodeAt(i);
    if (!(code > 47 && code < 58) && // numeric (0-9)
        !(code > 64 && code < 91) && // upper alpha (A-Z)
        !(code > 96 && code < 123)) { // lower alpha (a-z)
      return false;
    }
  }
  return true;
}

function getAxiosClient(cookies) {
	var headers = {'Content-Type': 'application/x-www-form-urlencoded'}
	if (Array.isArray(cookies)) {
		headers['Cookie'] =  cookies.join("; ")
	}
	
	var authClient = axios.create({
		  httpsAgent: new https.Agent({  
			rejectUnauthorized: false
		  }),
		  timeout: 3000,
		  headers: headers,
		});
	return authClient
}


function getUserHelpers(config ,model) {


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
				} else if (user && user.username && new String(user.username).length > 0) {
					//database.User.findOne(user._id)
					model.findUserByUsername(user.username).then(function(user) {
						if (user) {
							user.password = user && user.tmp_password && user.tmp_password.length > 0 ? user.tmp_password : (Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15));
							model.saveUser(user).then(function(res2) {
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
				//console.log(['REQUESTING TOKEN '])
				 return new Promise(function(resolve,reject) {
					 try {
						 var clientConfig = config.oauthClients[0]
						 var tokenParams={
							username: decodeURIComponent(user.username),
							password: decodeURIComponent(user.password),
							'grant_type':'password',
							'client_id':clientConfig.clientId,
							'client_secret':clientConfig.clientSecret,
							
						  };
						
						const params = new URLSearchParams();
						Object.keys(tokenParams).forEach(function(key) {
							params.append(key, tokenParams[key]);
						})	
						var client = getAxiosClient()
						  //console.log(params)
						  //console.log(config.authServer)
						  return client.post( config.authServer+"/token",params).then(function(loaded) {
							  var token = loaded.data
							  //console.log(token.access_token)
								//return response.json();
							//}).then(function(token) {
								if (token && token.access_token && token.access_token.length > 0) {
									user.token = token;
									resolve(user);
								} else {
									console.log(['ERROR REQUESTING TOKEN empty'])
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
                     var clientConfig = config.oauthClients[0]
                     //console.log(['rrT client',clientConfig])
					 var tokenParams={
                        refresh_token: refreshToken,
                        'grant_type':'refresh_token',
                        'client_id':clientConfig.clientId,
                        'client_secret':clientConfig.clientSecret
                      };
                    	//console.log('tokenParams')
						//console.log(tokenParams)
					
					  const params = new URLSearchParams();
						Object.keys(tokenParams).forEach(function(key) {
							params.append(key, tokenParams[key]);
						})	
						var client = getAxiosClient() //['refresh_token='+refreshToken])
                        client.post(config.authServer+"/token", params).then(function(data) {
                            //return response.json();
                        //}).then(function(token) {
							//console.log(data)
							var token = data.data
                            //console.log(['gotTTTT',token])
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
				var restrictions = config && config.passwordRestrictions && config.passwordRestrictions >= 0 && config.passwordRestrictions <= 4 ?  config.passwordRestrictions : 0
				try {
					var hasNumber =  /\d/.test( password)
					//console.log(['val',restrictions,hasNumber,password,isAlphaNumeric(password)])
					var length = password && typeof password.trim === 'function' ? password.trim().length : 0
					switch(restrictions) {
						case 0:
							return {valid: true}
						case 1:
							if (length > 5) {
								return {valid: true}
							} else {
								return {valid: false, message: 'Password must be at least six letters.'}
							}
						case 2:
							if (!hasNumber) {
								return {valid: false, message: 'Password must include at least one number.'}
							} else if (password.trim().length >7) {
								return {valid: true}
							} else {
								return {valid: false, message: 'Password must have at least eight letters.'}
							}
						case 3:
							if (!hasNumber) {
								return {valid: false, message: 'Password must include at least one number.'}
							} else if (!hasPunctuation) {
								return {valid: false, message: 'Password must include at least one number.'}
							} else if (length >7) {
								return {valid: true}
							} else {
								return {valid: false, message: 'Password must be at least eight letters.'}
							}
						case 4:
							if (length <= 7) {
								return {valid: false, message: 'Password must be at least eight letters.'}
							} else if (!hasNumber) {
								return {valid: false, message: 'Password must include at least one number.'}
							} else if (isAlphaNumeric(password)) {
								return {valid: false, message: 'Password must include at least one non alphanumeric symbol.'}
							} else{
								return {valid: true}
							}
					}
				} catch (e) {
					console.log(e)
					return {valid: false, message:'System error'}
				}
				
			}
        
        
            return {sanitizeUser, requestToken, requestRefreshToken, generateToken, loginSuccessJson, validatePassword}
        }
        
module.exports = getUserHelpers

var express = require('express');
const {ObjectId} = require('mongodb');
var fetch = require('node-fetch');
const mustache = require('mustache');
const crypto = require("crypto"); 
var faker = require('faker');
var btoa = require('btoa');
const mongoose = require('mongoose');
mongoose.Promise = Promise;
var md5 = require('md5');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bluebird = require('bluebird');
const OAuthServer = require('./express-oauth-server')
const database = require('./database');

var cors = require('cors')


async function getLoginSystemRouter(config) {
	//console.log(config) 
	var whitelist = config.allowedOrigins ? config.allowedOrigins.split(",") : []
	var localOrigin = new URL(config.loginServer).origin
	whitelist.push(localOrigin)
	var corsOptions = {
	  origin: function (origin, callback) {
		  //console.log(['CORS',origin,whitelist])
		if (whitelist.indexOf(origin) !== -1) {
		  callback(null, true)
		} else {
		  callback(new Error('Not allowed by CORS'))
		}
	  }
	}
 
		var connection = await mongoose.connect(config.databaseConnection, {useNewUrlParser: true, useUnifiedTopology: false}) 
		const model = require('./model_jwt')(database,config)
	           
        var oauthServer = new OAuthServer({
          model: model,
          grants: ['authorization_code', 'refresh_token','password'],
          accessTokenLifetime: config.jwtAccessTokenExpirySeconds, // 15 minutes
          allowEmptyState: true,
          allowExtendedTokenAttributes: true,
        })
        var {sanitizeUser, requestToken, generateToken, loginSuccessJson, requestRefreshToken, validatePassword} = require('./userHelpers')(config) //Object.assign({},config,{oauthServer: oauthServer}))
        const {sendWelcomeEmail} = require('./utils')(config)
            
        var passport = require('./passport')(config,database)

        
        /******************************************************
         * This module exports a router that includes routes for a login system and oauth server
         * 
         *****************************************************/

        var utils = require("./utils")(config)
        var ObjectId = require('mongodb').ObjectID;
        // INITIALSE OAUTH SERVER - create client if not exists
		database.OAuthClient.findOne({clientId: config.clientId}).then(function(client) {
			let clientFields = 	{
				clientId: config.clientId, 
				clientSecret:config.clientSecret,
				name:config.clientName,
				website_url:config.clientWebsite,
				privacy_url:config.
				clientPrivacyPage,
				redirectUris:[],
				image:config.clientImage
			};
			if (client!= null) {
				// OK
				database.OAuthClient.update({clientId:config.clientId},clientFields);
			} else {
				let client = new database.OAuthClient(clientFields);
				client.save().then(function(r) {
					
				});
			}
		}).catch(function(e) {
			console.log(e);
		});
		global.Promise = bluebird;

		var router = express.Router();
		router.options('*', cors())

		router.use(express.urlencoded());
		router.use(express.json());

		router.use(cookieParser());
		router.use(passport.initialize());
		
		router.post('/token', 
			oauthServer.token({
			  requireClientAuthentication: { // whether client needs to provide client_secret
				'authorization_code': false,
				'password': false,
			  },
			  //accessTokenLifetime: 3600,
			  //refreshTokenLifetime: 1209600,
			})
				
		)
		
		// TODO csrfCheck needs to be added to routes below
		// only suitable for single domain setup
		 //set csrf header
		//router.use('/',(req, res, next) => {
		  //if (config.csrfCheck) csrf.setToken(req, res, next)
		//});

		
		//// implement csrf check locally so fine grain selection of protected paths can be applied (leaving oauth paths public)
		//// can be enabled/disabled in configuration
		//let csrfCheck = function(req,res,next) { next()}
		//if (config.csrfCheck) {
			//csrfCheck = function(req,res,next) {
				//if (req.cookies && req.cookies['csrf-token'] && req.cookies['csrf-token'].length > 0) {
					//if (req.headers && req.headers['x-csrf-token'] && req.headers['x-csrf-token'].length > 0 && req.headers['x-csrf-token'] === req.cookies['csrf-token']) {
						//next();
					//} else if (req.query && req.query['_csrf'] && req.query['_csrf'].length > 0 && req.query['_csrf'] === req.cookies['csrf-token']) {
						//next();
					//} else if (req.body && req.body['_csrf'] && req.body['_csrf'].length > 0 && req.body['_csrf'] === req.cookies['csrf-token']) {
						//next();
					//} else {
						//res.send({error:'Failed CSRF check'});
					//}
				//} else {
					//res.send({error:'Failed CSRF check'});
				//}
			//} 
		//}
		
		
		router.post('/authorize', (req,res,next) => {
		  const {username, password} = req.body
		  if(username  && password) {
			  if (config.encryptedPasswords) {
				   req.body.user = model.getUser(username, md5(password))
			  } else {  
				req.body.user = model.getUser(username, password)
			  }
			return next()
		  }
		  const params = [ // Send params back down
			'client_id',
			'redirect_uri',
			'response_type',
			'grant_type',
			'state',
		  ]
			.map(a => `${a}=${req.body[a]}`)
			.join('&')
		  return res.redirect(config.loginServer + `/oauth?success=false&${params}`)
		}, (req,res, next) => { // sends us to our redirect with an authorization code in our url
		  return next()
		}, oauthServer.authorize({
		  authenticateHandler: {
			handle: req => {
			  return req.body.user
			}
		  }
		}))
	   
		 router.get('/refresh_token', (req,res,next) => {
			 try {
				 var token={}
				 if (req.cookies['refresh_token'] && req.cookies['refresh_token'].trim().length > 0 && req.cookies['refresh_token']!=="undefined") {
					 requestRefreshToken(req.cookies['refresh_token']).then(function(token) {
						//// SET NEW REFRESH TOKEN
						res.cookie('refresh_token',token.refresh_token,{httpOnly: true, maxAge: 604800000, secure: true, sameSite: 'None'})
						res.cookie('media_token',md5(token.refresh_token),{maxAge: 604800000, secure: true, sameSite: 'None'});
				  	    res.json(token)
					}).catch(function(e) {
						res.json({error:e})
					})
				  // if cookies fail, try query variable
				 } else if (req.query['refresh_token'] && req.query['refresh_token'].trim().length > 0 && req.query['refresh_token']!=="undefined") {
					requestRefreshToken(req.query['refresh_token']).then(function(token) {
					   res.json(token)
					}).catch(function(e) {
						res.json({error:e})
					})
				 } else {
					 res.json({error: 'Missing token'})
				 } 
			} catch (e) {
				   res.json({error:e})
			}
		 })
		 
		 
		// END CONFIGURE AND INITIALISE PASSPORT
		
		 
		/*********************************
		 * API ROUTES
		 *********************************/
		router.use('/buttons',function(req, res, next) {
				var buttons=[]
				if (config.googleClientId && config.googleClientId.trim() && config.googleClientId && config.googleClientId.trim()) {
					buttons.push('google')
				} 
				if (config.twitterConsumerKey && config.twitterConsumerKey.trim() && config.twitterConsumerSecret && config.twitterConsumerSecret.trim()) {
					buttons.push('twitter')
				}
				if (config.facebookAppId && config.facebookAppId.trim() && config.facebookAppSecret && config.facebookAppSecret.trim()) {
					buttons.push('facebook')
				}
				if (config.githubClientId && config.githubClientId.trim() && config.githubClientSecret && config.githubClientSecret.trim()) {
					buttons.push('github')
				}
				if (config.amazonClientId && config.amazonClientId.trim() && config.amazonClientSecret && config.amazonClientSecret.trim()) {
					buttons.push('amazon')
				}
				res.send({buttons: buttons.join(",")})
		})
		
		router.use('/login',function(req, res, next) {	 
			passport.authenticate('local', function(err, user, info) {
				loginSuccessJson(user,res,function(err,finalUser) {
					if (err) console.log(err);
					res.json({error:err,user:finalUser});
				})
			})(req, res, next);
		})  

		router.use('/google',function(req, res, next) {
			passport.authenticate('google', { scope: ['profile','email'] })(req,res,next);
		}) 
		
		router.get('/googlecallback', 
			passport.authenticate('google', { failureRedirect: '/login' }),
			function(req, res) {
				loginSuccessJson(req.user,res,function(err,user) {
					res.redirect(config.loginSuccessRedirect);
				});
			}
		);
		
		router.use('/twitter',function(req, res, next) {
			passport.authenticate('twitter', { scope: ['email'] })(req,res,next);
		}) 
		router.get('/twittercallback', 
		  passport.authenticate('twitter', { failureRedirect: '/login' }),
		  function(req, res, next)	 {
			loginSuccessJson(req.user,res,function(err,user) {
				res.redirect(config.loginSuccessRedirect);
			});
		});
		
		router.use('/facebook',function(req, res, next) {
			passport.authenticate('facebook', { scope: ['email'] })(req,res,next);
		}) 
		router.get('/facebookcallback', 
		  passport.authenticate('facebook', { failureRedirect: '/login' }),
		  function(req, res, next) {
			loginSuccessJson(req.user,res,function(err,user) {
				res.redirect(config.loginSuccessRedirect);
			});
		 });

		
		router.use('/github',function(req, res, next) {
		  passport.authenticate('github', { scope: ['user:email'] })(req,res,next);
		}) 
		router.get('/githubcallback', 
		  passport.authenticate('github', { failureRedirect: '/login' }),
		  function(req, res, next) {
				loginSuccessJson(req.user,res,function(err,user) {
					res.redirect(config.loginSuccessRedirect);
				});
		 });
		
		
		router.get('/amazon',
		  passport.authenticate('amazon', {scope: ['profile']}));

		router.get('/amazoncallback', 
		  passport.authenticate('amazon', { failureRedirect: '/login' }),
		  function(req, res, next) {
				loginSuccessJson(req.user,res,function(err,user) {
					res.redirect(config.loginSuccessRedirect);
				});
		  });
		
		
		/********************
		 * SIGNUP
		 ********************/
		router.post('/signup', cors(corsOptions),function(req, res) {
			//console.log('/signup')
				if (req.body.username && req.body.username.length > 0 && req.body.name && req.body.name.length>0 && req.body.avatar && req.body.avatar.length>0 && req.body.password && req.body.password.length>0 && req.body.password2 && req.body.password2.length>0) {
				if (!config.allowedUsers || config.allowedUsers.length === 0 ||  (config.allowedUsers.indexOf(req.body.username.trim()) >= 0 )) {
					
					var validateResult = validatePassword(req.body.password)
						//console.log(['VAL,PASS',validateResult,config.passwordRestrictions,req.body.password])
					if (!validateResult.valid) {
						res.send({error:validateResult.message});
					} else if (req.body.password2 != req.body.password)  {
						res.send({error:'Passwords do not match.'});
					} else {
						database.User.findOne({username:req.body.username.trim()}, function(err, ditem) {
							if (err) console.log(err)
							if (ditem) {
								res.send({'error':'There is already a user registered with the email address '+req.body.username});
							} else {
								let item = {}
								config.userFields.map(function(fieldName) {
									let key = fieldName.trim();
									item[key] = req.body[key] ? req.body[key].trim() : '';
								});
								if (config.encryptedPasswords) {
									item.password = md5(req.body.password.trim());
								} else {
									item.password = req.body.password.trim();
								}
								//console.log("CHECK AVATAR "+req.body.avatar)
								//database.User.find({}).then(function(allU) {
									//console.log(allU)
									
									database.User.findOne({avatar:{$eq:req.body.avatar.trim()}}).then(function(avUser) {
									//	console.log('AVUSER')
										//console.log(avUser)
											if (avUser!=null) {
												res.send({error:'Avatar name is already taken, try something different.'});
											} else {
												item.signup_token =  generateToken();
												item.signup_token_timestamp =  new Date().getTime();
												item.tmp_password=item.password;
												item.password='';
												item.password2='';
												let user = new database.User(item)
												user.save().then(function(result2) {
													res.send(sendWelcomeEmail(item.signup_token,req.body.name,item.username, req.body.apiUrl ? req.body.apiUrl : config.loginServer, req.body.linkBase));
												});                                        
											}
									}).catch(function(e) {
										console.log(e)
									});
								
								//})
							}
						});
					}
				} else {
					res.send({error:'Sorry. You are not allowed to register and login.'});
				}
			} else {
				res.send({error:'Missing required information.'});
			}
		});
		  

		/********************
		 * CONFIRM REGISTRATION 
		 ********************/
		router.get('/doconfirm',cors(corsOptions), function(req,res) {
			let params = req.query;
			if (params && params.code && params.code.length > 0) {
				database.User.findOne({ signup_token:params.code.trim()})
				.then(function(user)  {
						if (user != null) {
							if (new Date().getTime() - parseInt(user.signup_token_timestamp,10) < 600000) {
								
								var userId = user._id;
								user.password = user.tmp_password;
								user.signup_token = undefined;
								user.signup_token_timestamp =  undefined;
								user.tmp_password = undefined;
								user.save().then(function() {
									loginSuccessJson(user,res,function(err,user) {
										if (err) console.log(err);
										res.send({user: user})

										//res.redirect(config.loginSuccessRedirect);
									});
								});
						   } else {
							   res.send({error:'Token timeout. Refresh the page and try again'})
						   }
						} else {
							res.send({error:'Failed to find your confirm code. You may have already confirmed your registration'} );
						}
				   // }
				}).catch(function(e) {
					console.log(['failed',e]);
					res.send({error:e});
				});
			} else {
				res.send({error:'Invalid request missing code	'})
			}
		})


		/********************
		 * SIGN OUT
		 ********************/
		router.post('/logout',cors(corsOptions), oauthServer.authenticate(), function(req, res) {
			if (res.locals && res.locals.oauth && res.locals.oauth.token && res.locals.oauth.token.user && res.locals.oauth.token.user._id)  {
				database.OAuthRefreshToken.deleteMany({user:ObjectId(res.locals.oauth.token.user._id)}).then(function() {
				})
			}
			res.json({message:'Logged out'})
		});
		
		///********************
		 //* SIGN IN
		 //********************/
		//router.post('/signin',cors(corsOptions), function(req, res) {
			//if (req.body.username && req.body.username.length > 0 && req.body.password && req.body.password.length>0) {
				//var loginPassword = req.body.password.trim()
				//if (config.encryptedPasswords) {
					//loginPassword = md5(req.body.password.trim())
				//} 
				//database.User.findOne({username:req.body.username.trim(),password:loginPassword})
				//.then(function(user)  {
						//if (user != null) {
						   //loginSuccessJson(user,res,function(err,finalUser) {
								//if (err) console.log(err);
								//res.send({user: finalUser})
							//})
						//} else {
							//res.send({error: 'Login Failure'})
						//}
				//}).catch(function(e) {
					//res.send({error: 'Login Failure'})
				//});		
			//} else {
				//res.send({error: 'Login Failure'})
			//}
		//});

		
		/********************
		 * SIGN IN
		 ********************/
		router.post('/signinajax',cors(corsOptions), function(req, res) {
			//console.log(['ahax singin',req.body])
				
			if (req.body.username && req.body.username.length > 0 && req.body.password && req.body.password.length>0) {
				var loginPassword = req.body.password.trim()
				if (config.encryptedPasswords) {
					loginPassword = md5(req.body.password.trim())
				} 
				//console.log(['ahax singin',req.body,loginPassword])
				database.User.findOne({username:req.body.username.trim(),password:loginPassword})
				.then(function(user)  {
						if (user != null) {
						   loginSuccessJson(user,res,function(err,finalUser) {
								if (err) console.log(err);
								res.send({user: finalUser})
							})
						} else {
							res.send({error: 'Login Failure'})
						}
				}).catch(function(e) {
					res.send({error: 'Login Failure'})
				});		
			} else {
				res.send({error: 'Login Failure'})
			}
		});


		/********************
		 * REQUEST  PASSWORD RECOVERY EMAIL
		 ********************/
		router.post('/recover',cors(corsOptions), function(req, res) {
			if (req.body.email && req.body.email.length > 0) { // && req.body.code && req.body.code.length > 0) {
				var validateResult = validatePassword(req.body.password)
				if (!validateResult.valid) {
					res.send({error:validateResult.message});
				} else if (!req.body.password || req.body.password.length==0 || !req.body.password2 || req.body.password2.length==0) {
					res.send({error:'You must provide a new password.'});
				} else if (req.body.password2 != req.body.password)  {
					res.send({error:'Passwords do not match.'});
				} else {
					database.User.findOne({username:req.body.email}, function(err, user) {
					  if (err) {
						  res.send({error:err,here:1});
					  } else if (user!=null) {
						  if (config.encryptedPasswords) {
							  user.tmp_password = md5(req.body.password)
						  } else {
							user.tmp_password = req.body.password;
						  }
						  user.recover_password_token=generateToken(); //req.body.code;
						  user.recover_password_token_timestamp =  new Date().getTime();
						  // no update email address, item.username = req.body.username;
						  user.save().then(function(xres) {
							  var linkBase = req.body.linkBase
							   var link = (req.body.apiUrl ? req.body.apiUrl : config.loginServer) + '?code='+user.recover_password_token +  '#'+(linkBase ? linkBase : '')+'/dorecover'; 
							   var mailTemplate = config.recoveryEmailTemplate && config.recoveryEmailTemplate.length > 0 ? config.recoveryEmailTemplate : `<div>Hi {{name}}! <br/>

		To confirm your password recovery of your account , please click the link below.<br/>

		<a href="{{link}}" >Confirm your password update</a><br/>

		If you did not recently request a password recovery for your account, please ignore this email.<br/><br/>

										  </div>`;
							   
								var mailTemplateText = config.recoveryEmailTemplateText && config.recoveryEmailTemplateText.length > 0 ? config.recoveryEmailTemplateText : `Hi {{name}}! 

		To confirm your password recovery of your account , please open the link below.

		{{link}}

		If you did not recently request a password recovery for your account, please ignore this email.

										  `;
							   var mailTemplate =  mustache.render(mailTemplate,{link:link,name:user.name});
							   utils.sendMail(config.mailFrom,req.body.email,config.mailForgotPasswordSubject,
										 mustache.render(mailTemplate,{link:link,name:user.name}),
										 mustache.render(mailTemplateText,{link:link,name:user.name})
								)
								//.then(function(message) {  
									
								//})
								res.send({message: 'sent message'});
						  });  
						  
					  } else {
						  res.send({error:'No matching email address found for recovery.'});
					  }
					}); 
				}
			} else {
				res.send({error:'Missing required information.'});
			}
		});
		/********************
		 * PASSWORD RECOVERY 
		 ********************/
		router.get('/dorecover',cors(corsOptions),function(req,res) {
				let params = req.query;
				//console.log('params')
				//console.log(params)
				  database.User.findOne({ recover_password_token:params.code})
					.then(function(user)  {
						if (user != null) {
							//console.log(user)
							//console.log(new Date().getTime(), parseInt(user.recover_password_token_timestamp,10))
						  if (new Date().getTime() - parseInt(user.recover_password_token_timestamp,10) < 600000) {
							user.password = user.tmp_password;
							user.recover_password_token = undefined;
							user.recover_password_token_timestamp = undefined;
							user.tmp_password = undefined;
							var userId = user._id;
							  user.save().then(function() {
								 loginSuccessJson(user,res,function(err,finalUser) {
									//res.redirect(config.loginSuccessRedirect);
									if (err) console.log(err);
									res.send({user: finalUser})
								})
							  });
						   } else {
								  res.send({error: 'Token timeout.  Try to reset your password again.'});
						   }
						} else {
							res.send({error: 'Invalid code. You may have already confirmed your password update.'});
						}
					}).catch(function(e) {
						res.send({error:e });
					});		
		})



		/********************
		 * Update the access token and return the current user(+token) as JSON
		 ********************/
		router.post('/me',cors(corsOptions), oauthServer.authenticate(), function(req,res) {
			var code = ''
			var loginUser = res.locals && res.locals.oauth && res.locals.oauth.token && res.locals.oauth.token.user ? res.locals.oauth.token.user : {}
			res.json(loginUser)
			
		})

		/********************
		 * SAVE USER, oauthMiddlewares.authenticate
		 ********************/
		router.post('/saveuser',cors(corsOptions), oauthServer.authenticate(), function(req, res) {
			var loginUser = res.locals && res.locals.oauth && res.locals.oauth.token && res.locals.oauth.token.user ? res.locals.oauth.token.user : {}
			if (req.body._id && req.body._id.length > 0 && loginUser._id && loginUser._id === req.body._id) {
				// if password is sent, validate it
				var passwordOK = true
				if (req.body.password && req.body.password.length > 0 && req.body.password2 && req.body.password2.length > 0) {
					if (req.body.password2 != req.body.password)  {
						passwordOK = false
						res.send({error:'Passwords do not match'});
					} else {
						var validateResult = validatePassword(req.body.password)
						if (!validateResult.valid) {
							passwordOK = false
							res.send({error:validateResult.message});
						} 
					}
				}
				
				if (passwordOK) {
					database.User.findOne(ObjectId(req.body._id), function(err, user) {
						
					  if (err) {
						  res.send({error:err});
					  } else if (user!=null) {
						 config.userFields.map(function(fieldName) {
							let key = fieldName.trim();
							// don't update username
							if (key !== 'username' && key !== 'password') {
								user[key] = req.body[key] && req.body[key].trim  ? req.body[key].trim() : '';
							}
						 });
						
						 if (req.body.password && req.body.password.trim().length > 0 && req.body.password2 && req.body.password2.trim().length > 0 && req.body.password === req.body.password2) {
							  user.password=req.body.password.trim();
							  if (config.encryptedPasswords)  {
								  user.password = md5(user.password)
							  }
						 }
						
						  // update avatar only when changed
						  if (req.body.avatar && user.avatar != req.body.avatar) {
							  database.User.findOne({avatar:{$eq:req.body.avatar}}, function(err, avUser) {
								  if (avUser!=null) {
									  res.send({error:"Avatar name is already taken, try something different."});
								  } else {
									  if (user.username && user.username.length > 0 && user.name && user.name.length>0 && user.avatar && user.avatar.length>0) {
										  user.save().then(function(res) {
											  res.send({user, message:"Saved changes"});
										  });  
									  } else {
										  res.send({error:'Name and avatar cannot be empty'});
									  }
								  }
							  });
						  } else {
							  if (user.username && user.username.length > 0 && user.name && user.name.length>0 && user.avatar && user.avatar.length>0) {
								user.save().then(function(xres) {
								  res.send({user, message:"Saved changes"});
								});  
							} else {
								 res.send({error:"Name and avatar cannot be empty"});
							}
						  }
					  } else {
						  res.send({error:'Invalid save request cannot find user'});
					  }
					}); 
				}
			} else {
				res.send({error:'No permission to save this user'});
			}
		});
		
		router.get('/test',cors(), function(req,res) {
			res.json({OK: true})
		})
		const csrf = require('./csrf')
		
		
		
		
		// error handlers
		router.use((req, res, next) => {
		  const err = new Error('Not Found');
		  err.status = 404;
		  next(err);
		});

		router.use((err, req, res, next) => {
		  res.status(err.status || 500);
		  //console.log(err);
		  res.json({
			message: err.message,
			error: err
		  });
		});
		return {router:router, authenticate: oauthServer.authenticate(), csrf:csrf, database: database} 
}





module.exports =  getLoginSystemRouter


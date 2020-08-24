//let config = global.gConfig;
var md5 = require('md5');
const crypto = require("crypto"); 
var faker = require('faker');
//const database = require('./database');

function generatePassport(config,database) {
// CONFIGURE AND INITIALISE PASSPORT 
	var passport = require('passport')

	passport.serializeUser(function(user, done) {
	  done(null, user);
	});

	passport.deserializeUser(function(user, done) {
	  done(null, user);
	});
	

	// CALLBACK TO SUPPORT PASSPORT STRATEGIES
	function findOrCreateUser(name,email,cb) {
		if (email && email.length > 0) {
			if (!config.allowedUsers || config.allowedUsers.length === 0 ||  (config.allowedUsers.indexOf(email.toLowerCase().trim()) >= 0 )) {
				 database.User.findOne({username:email.trim()}).then(function(user) {
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
			} else {
				cb('Not allowed to register', null);
			}		 
		} else {
			cb('no user', null);
		}
	}


	var LocalStrategy = require('passport-local').Strategy;

	// username/password
	passport.use(new LocalStrategy(
	  function(username, password, done) {
		database.User.findOne({ username: username,password:password }, function (err, user) {
		  if (err) { return done(err); }
		  if (!user) {
			return done(null, false, { message: 'Incorrect login details' });
		  }
		  return done(null, user);
		});
	  }
	));

    if (config.googleClientId && config.googleClientSecret) { 
        var GoogleStrategy = require('passport-google-oauth20').Strategy;
        passport.use(new GoogleStrategy({
            clientID: config.googleClientId,
            clientSecret: config.googleClientSecret,
            callbackURL: config.authServer + '/googlecallback',
            userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
          },
          function(accessToken, refreshToken, profile, cb) {
            if (profile && profile.emails && profile.emails.length > 0) {
                    let email = profile.emails[0].value
                    findOrCreateUser(profile.displayName,email,cb);
                } else {
                    cb('google did not provide an email',null);
                }
            }
        ));
    }


    if (config.twitterConsumerKey && config.twitterConsumerSecret) {
        var TwitterStrategy = require('passport-twitter').Strategy;
        passport.use(new TwitterStrategy({
            consumerKey: config.twitterConsumerKey,
            consumerSecret: config.twitterConsumerSecret,
            callbackURL: config.authServer + '/twittercallback',
            userProfileURL: "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true"
          },
          function(token, tokenSecret, profile, cb) {
                if (profile && profile.emails && profile.emails.length > 0) {
                    let email = profile.emails[0].value
                    findOrCreateUser(profile.displayName,email,cb);
                } else {
                    cb('twitter did not provide an email',null);
                }
          }
        ));
    }

    if (config.facebookAppId && config.facebookAppSecret) {
        var FacebookStrategy = require('passport-facebook').Strategy;
        passport.use(new FacebookStrategy({
            clientID: config.facebookAppId,
            clientSecret: config.facebookAppSecret,
            callbackURL: config.authServer + '/facebookcallback',
            profileFields: ['id', 'displayName', 'photos', 'email']
          },
          function(token, tokenSecret, profile, cb) {
                if (profile && profile.emails && profile.emails.length > 0) {
                    let email = profile.emails[0].value
                    findOrCreateUser(profile.displayName,email,cb);
                } else {
                    cb('FacebookStrategy did not provide an email',null);
                }
          }
        ));
    }
	

	if (config.githubClientId && config.githubClientSecret) {
        var GithubStrategy = require('passport-github2').Strategy;
        passport.use(new GithubStrategy({
            clientID: config.githubClientId,
            clientSecret: config.githubClientSecret,
            callbackURL: config.authServer+"/githubcallback",
          },
          function(accessToken, refreshToken, profile, cb) {
            if (profile && profile.emails && profile.emails.length > 0) {
                let email = profile.emails[0].value
                findOrCreateUser(profile.displayName ? profile.displayName : profile.username,email,cb);
            } else {
                cb('github did not provide an email',null);
            }
          }
        ));
    }
    
    if (config.amazonClientId && config.amazonClientSecret) {
        var AmazonStrategy = require('passport-amazon').Strategy;
        passport.use(new AmazonStrategy({
            clientID: config.amazonClientId,
            clientSecret: config.amazonClientSecret,
            callbackURL: config.authServer+"/amazoncallback",
          },
          function(accessToken, refreshToken, profile, cb) {
            if (profile && profile.emails && profile.emails.length > 0) {
                let email = profile.emails[0].value
                findOrCreateUser(profile.displayName ? profile.displayName : profile.username,email,cb);
            } else {
                cb('amazon did not provide an email',null);
            }
          }
        ));
    }
    return passport
}    
module.exports = generatePassport

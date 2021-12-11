var md5 = require('md5');
const crypto = require("crypto"); 
var faker = require('faker');

function generatePassport(config,model) {
// CONFIGURE AND INITIALISE PASSPORT 
	var passport = require('passport')

	passport.serializeUser(function(user, done) {
	  done(null, user);
	});

	passport.deserializeUser(function(user, done) {
	  done(null, user);
	});
	


	var LocalStrategy = require('passport-local').Strategy;

	// username/password
	passport.use(new LocalStrategy(
	  function(username, password, done) {
      if (!username || !password) {
        return done(null, false, { message: 'Missing credentials' });
      }
      model.findUserByUsername(username, password).then(function(user) {
          //database.User.findOne({ username: username,password:password }, function (err, user) {
        // if (err) { return done(err); }
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
                    model.findOrCreateUser(profile.displayName,email,cb);
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
                    model.findOrCreateUser(profile.displayName,email,cb);
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
                    model.findOrCreateUser(profile.displayName,email,cb);
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
                model.findOrCreateUser(profile.displayName ? profile.displayName : profile.username,email,cb);
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
                model.findOrCreateUser(profile.displayName ? profile.displayName : profile.username,email,cb);
            } else {
                cb('amazon did not provide an email',null);
            }
          }
        ));
    }
    return passport
}    
module.exports = generatePassport

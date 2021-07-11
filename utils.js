const nodemailer = require('nodemailer');
//const nodemailerSendgrid = require('nodemailer-sendgrid');
const mustache = require('mustache');
const sgMail = require('@sendgrid/mail');
const jwt = require('jsonwebtoken');

        
function getUtilFunctions(config) {
//console.log('GET UTIL FUNS')
	function userFromAuthHeaders(req,res,next) {
		let token = req.headers.authorization ? req.headers.authorization : ((req.query && req.query.id_token) ? req.query.id_token : null)
		if (token && token.indexOf('Bearer ') === 0) {
			token = token.slice(7)
		}
		if (token) { 
			var emailDirect = '';
			try {
				const decoded = jwt.verify(token,process.env.jwtAccessTokenSecret)
				//console.log(['decoded',JSON.stringify(decoded)]) //,err.message
				res.locals.user=decoded ? decoded.user : null
				
				//	res.send('OKYDOKE '+(res.locals.user ? res.locals.user.avatar : ''))
				//});
				//console.log(JSON.stringify(unverifiedDecodedAuthorizationCodeIdToken))
				//emailDirect = unverifiedDecodedAuthorizationCodeIdToken && unverifiedDecodedAuthorizationCodeIdToken.payload ? unverifiedDecodedAuthorizationCodeIdToken.payload.email : '';
				//res.locals.user={email:emailDirect}
				//console.log(['set user from token',emailDirect])
			} catch (e) {
				console.log('ERRRR')
				console.log(['err',e.toString()])
			}
		}
		next() //req,res,next)
	}



    function sendMailSendGrid(from,to,subject,html,text) {
        //console.log(['SENDGRID SEND',config.sendGridApiKey,from,to,subject,html,text])
        sgMail.setApiKey(config.sendGridApiKey);
        const msg = {
          to: to,
          from: from, // Use the email address or domain you verified above
          subject: subject,
          text: text,
          html: html,
        };
        return new Promise(function(resolve,reject) {
			sgMail
			  .send(msg, (error, result) => {
				  if (error) {
					  console.log(error)
					   const {message, code, response} = error;
					   console.log([message, code, response])
					   resolve('Failed to send email')
				  } else {
					  resolve('Sent email')
				  }
				  
			   })
		})
          //.then(() => {}, error => {
            //console.log(error);

            //if (error.response) {
              //console.log(error.response.body)
            //}
          //});
    }

    function sendMail(from,to,subject,html,text) {
		return new Promise(function(resolve,reject) {
			var transporter = null
			if (config.sendGridApiKey) {
				try {
					sendMailSendGrid(from,to,subject,html,text).then(function(message) {
						resolve(message)
					})
				} catch (e) {
					console.log(e)
					resolve('Failed to send email')
				}
			} else if (nodemailer && nodemailer.createTransport && config.transport) {
				try { 
					transporter = nodemailer.createTransport(config.transport);
					//console.log(['transport',transporter,config.sendGridApiKey,config.transport])
					if (transporter) {
						var mailOptions = {
						  from: from,
						  to: to,
						  subject: subject,
						  html: html
						};
						console.log(mailOptions);
						transporter.sendMail(mailOptions, function(error, info){
						  if (error) {
							console.log(error);
							//res.send('FAIL');
							resolve('Failed to send email')
						  } else {
							console.log('Email sent: ' + info.response);
							resolve('Sent email')
							//res.send('OK');
						  }
						});
					}
				} catch (e) {
					console.log(e)
					resolve('Failed to send email')
				}
			}
		})
    }
     
    function sendWelcomeEmail(token,name,username, authServer = null, linkBase) {
        var link = (authServer ? authServer : config.authServer) + '?code='+token + '#'+(linkBase ? linkBase+'/doconfirm' : '/doconfirm');
        
        var mailTemplate = config.signupEmailTemplate && config.signupEmailTemplate.length > 0  ? config.signupEmailTemplate : `<div>Hi {{name}}! <br/>

                Welcome,<br/>

                To confirm your registration, please click the link below.<br/>

                <a href="{{link}}" >Confirm registration</a><br/>

                If you did not recently register, please ignore this email.<br/><br/>

                </div>`
        var mailTemplateText = config.signupEmailTemplateText && config.signupEmailTemplateText.length > 0  ? config.signupEmailTemplateText : `Hi {{name}}! 

                Welcome,

                To confirm your registration, please open the link below.

                {{link}}

                If you did not recently register, please ignore this email.

                
                `        
        sendMail(config.mailFrom,username,config.mailRegisterTopic,
            mustache.render(mailTemplate,{link:link,name:name}),
            mustache.render(mailTemplateText,{link:link,name:name})
        );
        var item={}
        item.message = 'Check your email to confirm your sign up.';
        return item;
    }
    
    function createClients(config,database) {
			//console.log(['CREATE AUTH CLIENTS',config.oauthClients])
			return new Promise(function(resolve,reject) {
				var promises = []
				if (Array.isArray(config.oauthClients)) {
					config.oauthClients.forEach(function(clientConfig) {
						//console.log(['CREATE AUTH CLIENT',clientConfig.clientId])
						database.OAuthClient.findOne({clientId: clientConfig.clientId}).then(function(result) {
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
								promises.push(database.OAuthClient.update({clientId:clientConfig.clientId},clientFields))
							} else {
								//console.log('CREATE push save');
								let client = new database.OAuthClient(clientFields);
								promises.push(client.save())
							}
							Promise.all(promises).then(function(res) {
								//console.log(['CREATED AUTH CLIENTS',res])
								//database.OAuthClient.find({}).then(function(foundClients) {
									//console.log(['CREATED AUTH CLIENTS found',foundClients])
									resolve()
								//})
							})
						}).catch(function(e) {
							//console.log('CREATE AUTH ERR');
							console.log(e);
							resolve()
						}) 
					})
				}
				
			})
		}


    let utilFunctions =  {
      sendWelcomeEmail, sendMail, userFromAuthHeaders, createClients
    }
    return utilFunctions
}

module.exports = getUtilFunctions;

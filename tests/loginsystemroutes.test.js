//const request = require('request');
global.XMLHttpRequest = undefined
const nodemailer = require('nodemailer');
const sendgridmailer = require('@sendgrid/mail');
//console.log([nodemailer, sendgridmailer])
const axiosLib = require('axios');
const https = require('https');
const fs = require('fs');
//var utilsMock = jest.mock('../utils')
//const utils = require('../utils')
const loginSystem = require('express-oauth-login-system-server')
const express = require('express');
const config = require('./test-config')
const dbHandler = require('./db-handler');
const User = require('../database/User')
const OAuthClient = require('../database/OAuthClient')

var app = null

var server = null

const ORIGIN = 'https://localhost:5100'
const baseUrl = ORIGIN
const samplePassword='aaaaaa8?'
const altSamplePassword='bbbbbb8?'
// TODO
// token timeout on confirm/signup - register/forgot then hack timeout in db before attempting doconfirm/doforgot and expecting fail err msg


function getAxiosClient(token,cookies,origin) {
	var headers = {'Origin': origin ? origin : ORIGIN}
	if (token) {
		headers['Authorization'] =  'Bearer '+token
	}
	if (cookies) {
		headers['Cookie'] =  cookies.join("; ")
	}
	//console.log(['AX',headers]) 
	var authClient = axiosLib.create({
		  baseURL: baseUrl,
		  timeout: 3000,
		  headers: headers,
		  withCredentials: true,
		  httpsAgent: new https.Agent({  
			rejectUnauthorized: false
		  }),
		  adapter: require('axios/lib/adapters/http')
		});
	return authClient
}

const axios = getAxiosClient()

/**
 * Connect to a new in-memory database before running any tests.
 */
beforeAll(async () => {
	var uri = await dbHandler.connect()
	const login = await loginSystem(Object.assign({},config, {databaseConnection:uri, authServer:ORIGIN, loginServer:ORIGIN+"/"}))
	app = express();
	app.use(login.router)
	const port=5100
	server =  https.createServer({
		key: fs.readFileSync('./tests/key.pem'),
		cert: fs.readFileSync('./tests/cert.pem'),
	}, app).listen(port, () => {
	  //console.log(`Login server listening  at https://localhost:`+port)
	}) 
});

/**
 * Clear all test data after every test.
 */
afterEach(async () => await dbHandler.clearDatabase());

beforeEach(async () => {
	var clients = await OAuthClient.deleteMany({})
	var clientConfig = config.oauthClients[0]
	var client = new OAuthClient({
			clientId: clientConfig.clientId, 
			clientSecret:clientConfig.clientSecret,
			name:clientConfig.clientName,
			website_url:clientConfig.clientWebsite,
			privacy_url:clientConfig.clientPrivacyPage,
			redirectUris:Array.isArray(clientConfig.redirectUris) ? clientConfig.redirectUris : '',
			image:''
		})
	await client.save()
})

/**
 * Remove and close the db and server.
 */
afterAll(async () => {
	await dbHandler.closeDatabase()
	server.close()
});

/**
 * Test Helpers
 */
 
function hasCookie(cookie, cookies) {
	var found = false
	if (Array.isArray(cookies)) {
		cookies.forEach(function(c) {
			if (c.indexOf(cookie) === 0) {
				found = true
			}
		})
	}
	return found
} 
 
async function signupAndConfirmUser(name,username=null, avatar=null) {
	// post create new user
	var data = {name: name,username:username ? username : name,avatar: avatar ? avatar : name,password:samplePassword,password2:samplePassword}
	//console.log(data)
	//try {
		var cres = await axios.post('/signup',data)
		//console.log(cres)
		expect(cres.data.message).toBe('Check your email to confirm your sign up.')
		// check cookies
		var cookies = cres.headers.['set-cookie']
		// check user in db
		var res = await User.findOne({username:username ? username : name})
		expect(res.signup_token).toBeTruthy()
		expect(parseInt(res.signup_token_timestamp)).toBeGreaterThan(0)
		// do confirmation
		var rres = await axios.get('/doconfirm?code='+res.signup_token)
		var cookies2 = rres.headers.['set-cookie']
		expect(hasCookie('refresh_token',cookies2)).toBe(true)
		expect(hasCookie('media_token',cookies2)).toBe(true)
		
		return rres
	//} catch (e) {
		//console.log(e)
	//}
}


/**
 * TESTS
 */

describe('login system routes', () => {
    it('responds with status 404 on invalid endoint',async () => {
		var meres = null
		try {
			meres = await axios.get('/badendpoint')
		} catch (e) {
			expect(e.response.status).toEqual(404)
		}
	})
	
	it('can load all oauth client public details unauthenticated',async () => {
		var axiosClient = getAxiosClient()
		var meres = await axiosClient.get('/oauthclientspublic')
		//console.log(meres.data)
		expect(meres.data[0].clientId).toBe('test')
		expect(meres.data[0].clientName).toBe('test client')
	})
	
	
	it('can load all oauth client details',async () => {
		var rres = await signupAndConfirmUser('johnson')
		var token=rres.data.user.token.access_token
		var axiosClient = getAxiosClient(token)
		var meres = await axiosClient.get('/oauthclients')
		//console.log(meres)
		expect(meres.data[0].clientSecret).toBe('testpass')
	})
	
	it('fails CORS checks for signin, doconfirm, recover, dorecover, signinajax, logout, me, saveuser endpoints with bad origin',async () => {
		var meres = null
		var rres = await signupAndConfirmUser('johnson')
		var token=rres.data.user.token.access_token
		var badClient = getAxiosClient(token,null,'http://localhost:8000')
		//signin
		try {
			meres = await badClient.post('/signinajax',{username:'johnson',password:samplePassword})
			
		} catch (e) {
			//console.log(e)
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		//// doconfirm
		try {
			meres = await badClient.get('/doconfirm',{code:'sdfg4345df'})
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		//forgot
		try {
			meres = await badClient.post('/recover',{username:'john',password:samplePassword,password2:samplePassword})
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		// doforgot
		try {
			meres = await badClient.get('/dorecover',{code:'lkj;oa89sdf0'})
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		// signinajax
		try {
			meres = await badClient.post('/signinajax',{username:'john',password:samplePassword})
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		// logout
		try {
			meres = await badClient.post('/logout')
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		// me
		try {
			meres = await badClient.post('/me')
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
		// saveuser
		try {
			meres = await badClient.post('/saveuser',{_id:'2234234',username:'john',password:samplePassword})
			
		} catch (e) {
			expect(e.response.status).toEqual(500)
			expect(e.response.data.message).toEqual('Not allowed by CORS')
		}
	})
    
    it('can get a token through user signup flow then load /me endpoint',async () => {
		sendgridmailer.send.mockReset()
		var rres = await signupAndConfirmUser('john')
		var token=rres.data.user.token.access_token
		// check sendgrid was called
		expect(sendgridmailer.send.mock.calls.length).toBe(1);
		// test me endpoint
		var authClient = getAxiosClient(token)
		var meres = await authClient.post('/me')
		expect(meres.data.name).toEqual('john')
	})
	
	it('fails validation on signup when missing/invalid data',async () => {
		var rres = await signupAndConfirmUser('john','jbell','belly')
		// conflict with existing user
		var cres = await axios.post('/signup',{name: 'john',username:'jbell',avatar:'bello',password:samplePassword,password2:samplePassword})
		expect(cres.data.error.indexOf('There is already a user registered with the email address ')).toBe(0)
		// conflict with existing  avatar
		var cres = await axios.post('/signup',{name: 'john',username:'jbell332',avatar:'belly',password:samplePassword,password2:samplePassword})
		//console.log(cres)
		expect(cres.data.error).toBe('Avatar name is already taken, try something different.')
		
		var name='fred'
		// missing name
		var cres = await axios.post('/signup',{name: '',username:name,avatar:name,password:samplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Missing required information.')
		// missing username
		var cres = await axios.post('/signup',{name: name,username:'',avatar:name,password:samplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Missing required information.')
		// missing avatar
		var cres = await axios.post('/signup',{name: name,username:name,avatar:'',password:samplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Missing required information.')
		// missing password
		var cres = await axios.post('/signup',{name: name,username:name,avatar:name,password:'',password2:''})
		expect(cres.data.error).toBe('Missing required information.')
		// password mismatch
		var cres = await axios.post('/signup',{name: name,username:name,avatar:name,password:altSamplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Passwords do not match.')
		
	})
	
	it('fails validation on recover when missing data',async () => {
		var name='fred'
		// missing email
		var cres = await axios.post('/recover',{name: name,email:'',password:samplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Missing required information.')
		// missing password
		var cres = await axios.post('/recover',{name: name,email:name,password:'',password2:''})
		expect(cres.data.error).toBe('Password must be at least eight letters.')
		// password mismatch
		var cres = await axios.post('/recover',{name: name,email:name,password:altSamplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('Passwords do not match.')
		// no such user
		var cres = await axios.post('/recover',{name: name,email:'notauser',password:samplePassword,password2:samplePassword})
		expect(cres.data.error).toBe('No matching email address found for recovery.')
		
	})
    
    
    it('can change password through forgot password flow',async () => {
		await signupAndConfirmUser('bill')
		// start recover with new pw bbb
		var meres = await axios.post('/recover',{name:'bill',email:'bill',password:altSamplePassword,password2:altSamplePassword})
		res = await User.findOne({name:'bill',username:'bill'})
		expect(res.recover_password_token).toBeTruthy()
		expect(parseInt(res.recover_password_token_timestamp)).toBeGreaterThan(0)
		
		// do recover
		var dores = await axios.get('/dorecover?code=' + res.recover_password_token)
		var ares = await User.findOne({name:'bill',username:'bill'})
		expect(ares.recover_password_token).not.toBeTruthy()
		expect(ares.password).toBe(altSamplePassword)
	})
	
	
	 it('can save user changes',async () => {
		var rres = await signupAndConfirmUser('bill')
		var token=rres.data.user.token.access_token
		//// save changes
		var authClient = getAxiosClient(token)
		try {
			var cres = await authClient.post('/saveuser',{_id:rres.data.user._id, name: 'jill',username:'jill',avatar:'jill'})
			expect(cres.data.message).toBe('Saved changes')
		} catch (e) {
			console.log(e)
		}
	})
    
    it('can use refresh token in uri',async () => {
		var rres = await signupAndConfirmUser('bill')
		var token=rres.data.user.token.access_token
		//// save changes
		var authClient = getAxiosClient()
		var cres = await authClient.get('/refresh_token?refresh_token='+rres.data.user.token.refresh_token)
		expect(cres.data.access_token).toBeTruthy()
	})
    
    it('can load buttons',async () => {	
		// post create new user
		var cres = await axios.get('/buttons')
		//console.log(cres.data)
		expect(cres.data.buttons).toEqual('google,twitter,facebook,github,amazon')	
	})
	
	it('can get a token using refresh token cookies',async () => {
		var rres = await signupAndConfirmUser('jane')
		var token=rres.data.user.token.access_token
		var cookies = rres.headers["set-cookie"]
		//axios.defaults.headers.Cookie = cookie;
		var authClient = getAxiosClient(null,cookies)
		var rres = await authClient.get('/refresh_token')
		expect(rres.data.access_token).toBeTruthy()
	})
    
    
	it('can logout',async () => {
		var rres = await signupAndConfirmUser('jane')
		var token=rres.data.user.token.access_token
		var cookies = rres.headers["set-cookie"]
		//axios.defaults.headers.Cookie = cookie;
		var cookieClient = getAxiosClient(null,cookies)
		var cres = await cookieClient.get('/refresh_token')
		expect(cres.data.access_token).toBeTruthy()
		var authClient = getAxiosClient(token)
		var logoutRes = await authClient.post('/logout')
		// TODO update refresh cookie from ..
		cres = await cookieClient.get('/refresh_token')
		expect(cres.data.access_token).not.toBeTruthy()
	})
});

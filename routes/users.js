var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');



// Register
router.get('/register', function(req, res){
	res.render('register');
});

// Login
router.get('/login', function(req, res){
	res.render('login');
});

// Register User
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;
	var employee_id=req.body.employee_id;
	var  mobile_no=req.body.mobile_no;
	var department=req.body.department;
	var designation=req.body.designation;
	var security_ques=req.body.security_ques;
	var security_ans=req.body.security_ans;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);
	req.checkBody('employee_id','Employee id is required').notEmpty();
    req.checkBody('mobile_no','mobile no is required').isInt();
    req.checkBody('department','Department Name is required').notEmpty();
    req.checkBody('designation','Designation is required').notEmpty();
    req.checkBody('security_ques','Security question is required').notEmpty();
    req.checkBody('security_ans','Security answer does not match').equals(req.body.security_ques);



	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors:errors
		});
	}


	else {
		var newUser = new User({
			name: name,
			email:email,
			username: username,
			password: password,
			mobile_no:mobile_no,
			department:department,
             designation:designation,
             security_ques:security_ques,
              security_ans:security_ans,
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
			console.log(user);
		});

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/users/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Unknown User'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Invalid password'});
   		}
   	});
   });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;
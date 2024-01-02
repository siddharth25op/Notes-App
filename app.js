const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const env = require('dotenv').config();
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
const fotp = otp;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URL);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    name: String,
    googleId: String,
    discordId: String,
    profilePic: String,
    avatar: String,
    verified: Number
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

const noteSchema = new mongoose.Schema({
    title: String,
    content: String,
    pId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const Note = mongoose.model("Note", noteSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, {
            id: user.id,
            username: user.username,
            name: user.name,
            profilePic: user.profilePic,
            avatar: user.avatar,
            discordId: user.discordId,
            verified: user.verified
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id,
            name: profile.displayName,
            username: profile.emails[0].value,
            profilePic: profile.photos[0].value,
            verified: 1
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new DiscordStrategy({
        clientID: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        callbackURL: process.env.DISCORD_CALLBACK_URL
    },
    function (accessToken, refreshToken, identify, cb) {
        User.findOrCreate({
            discordId: identify.id,
            name: identify.global_name,
            avatar: identify.avatar,
            username: identify.username,
            verified: 1
        }, function (err, user) {
            return cb(err, user);
        });
    }));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

app.get("/auth/google/notes", passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        res.redirect("/notes");
    }
);

app.get("/auth/discord", passport.authenticate("discord", {
    scope: ["identify"]
}));

app.get("/auth/discord/notes", passport.authenticate("discord", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        res.redirect("/notes");
    }
);

app.get("/login", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/notes");
    } else {
        res.render("login");
    }
});

app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/notes");
    } else {
        res.render("register");
    }
});

app.get("/notes", async function (req, res) {
    try {
        if (req.isAuthenticated()) {
            const notes = await Note.find({ pId: req.user.id });
            //const existingUser = await User.findOne({ username: req.body.username });
            //console.log(req.user);
            if(req.user.verified == 1){
            res.render("notes", {
                name: req.user.name,
                id: req.user.id,
                notes: notes,
                username: req.user.username,
                profilePic: req.user.profilePic,
                avatar: req.user.avatar,
                discordId: req.user.discordId
            });
        }else{
            const username = req.user.username
            sendOtp(username);
            res.render("verify", {
              error: `We have sent you an verification code on ${username}`,
              username: username
            });
          }
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.log(err);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/submit", async (req, res) => {
    const title = req.body.title;
    const content = req.body.content;

    try {
        const note = new Note({ title, content, pId: req.user.id });
        await note.save();
        res.redirect("/notes");
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post("/edit-delete", async (req, res) => {
    const { title, content, noteId, delete: isDelete } = req.body;
    try {
        if (isDelete) {
            const deletedNote = await Note.findByIdAndDelete(noteId);
            if (!deletedNote) {
                return res.status(404).json({ error: 'Note not found' });
            }
            res.redirect("/notes");
        } else {
            let note;
            if (noteId) {
                note = await Note.findByIdAndUpdate(noteId, { title, content }, { new: true });
            } else {
                note = new Note({ title, content });
                await note.save();
            }
            res.redirect("/notes");
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.post("/register", async function (req, res) {
    try {
        const existingUser = await User.findOne({ username: req.body.username });
        if (existingUser) {
            return res.render("register", { error: "Username is already taken. Please choose another." });
        }
        const username = req.body.username;
        User.register({
            username: req.body.username,
            name: req.body.name
        }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                return res.render("register", { error: "Registration failed. Please try again." });
            }

            passport.authenticate("local")(req, res, function () {
                sendOtp(username);
                return res.render("verify", {
                    error: `We have sent you an verification code on ${username}`,
                    username: req.body.username
                });
            });
        });
    } catch (error) {
        console.log(error);
        return res.render("register", { error: "An error occurred. Please try again." });
    }
});

app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    passport.authenticate("local", function (err, user, info) {
        if (err) {
            console.log(err);
            return res.render("login", { error: "An unexpected error occurred." });
        }
        if (!user) {
            return res.render("login", { error: "Invalid username or password." });
        }

        if (user.salt == null) {
            return res.render("login", {
                error: "This is already exist with google. Please login with google."
            });
        }

        req.login(user, function (err) {
            if (err) {
                console.log(err);
                return res.render("login", { error: "An unexpected error occurred." });
            }
            return res.redirect("/notes");
        });
    })(req, res);
});

app.get("/forgot-password", function(req, res) {
    res.render("forgot-password");
})

app.post("/forgot-password", async (req, res) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.MY_PASSWORD,
            },
        });

        const token = jwt.sign({
                data: process.env.TOKEN_DATA,
            },
            process.env.JWT_VERIFICATION_SECRET, {
                expiresIn: '10m'
            }
        );

        const mailConfigurations = {
            from: process.env.MY_EMAIL,
            to: req.body.email,
            subject: 'Email Verification',
            text: `Hi! There, You have recently requested to reset your password.\nPlease follow the given link to reset your password http://localhost:3000/verify/${token}/${req.body.email}\nThanks`,
        };

        const info = await transporter.sendMail(mailConfigurations);

        console.log('Email Sent Successfully');
        //console.log(info);

        res.render('forgot-password', {
            error: `We have sent you an email on ${req.body.email}`,
        });
    } catch (error) {
        console.error(error);
        res.status(500).render('forgot-password', {
            error: 'Email does not exist or there was an issue sending the email.',
        });
    }
});

app.get('/verify/:token/:username', (req, res) => {
    const { token } = req.params;
    const { username } = req.params;
    jwt.verify(token, process.env.JWT_VERIFICATION_SECRET, function(err, decoded) {
        if (err) {
            console.log(err);
            res.send("Email verification failed, possibly the link is invalid or expired");
        } else {
            console.log("Email verified successfully.");
            res.render("reset-password", {
              username: username
            });
        }
    });
});

app.post("/reset-password", async function(req, res) {
    const username = req.body.email;
    const user = await User.findOne({ username: username });

    user.setPassword(req.body.password, async () => {
        await user.save();
        res.render("login", { 
            error: "Password reset successful. Please login with your new password." 
        });
    });
})

async function sendOtp(username){
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.MY_PASSWORD,
            },
        });
        
        const mailConfigurations = {
            from: "Uzumaki Notes App",
            to: username,
            subject: 'Email Verification',
            text: `Hi! There, your verification code is ${otp}`,
        };

        const info = await transporter.sendMail(mailConfigurations);

        console.log('Email Sent Successfully');
        //console.log(info);
}

app.post("/otp", async function(req, res){
  if(req.body.otp == fotp){
    const username = req.body.username;
    await User.updateOne({ username: username }, { $set: { verified: 1 } });
    res.render("login", {
        error: "Verification succeeded. Please login"
    });
  }else{
    res.render("verify", {
        error: "Invalid OTP"
    })
  }
});

app.listen(3000, function () {
    console.log("server is running on port 3000");
});

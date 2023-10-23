import passport from 'passport';
import LocalStrategy from 'passport-local';
import db from '../../db.mjs';

passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    db.getUser(id)
        .then(user => {
            return {
                _id: user._id,
                name: user.name,
                email: user.email,
                isAdmin: user.is_admin,
                apiAccess: user.api_access,
                authId: user.authId,
                created: user.created
            };
        })
        .then(user => done(null, user));
});

export default function(app, options) {
    options.successRedirect ?? '/account';
    options.failureRedirect ?? '/login';

    return {
        init: function() { 
            passport.use(
                new LocalStrategy(function verify(username, password, cb) {
                    db.checkLogin(username, password).then((user) => {
                        if (user.validLogin) {
                            return cb(null, user);
                        }
                        return cb(null, false, {
                            message: 'Incorrect username or password.'
                        });
                    });
                })
            );
            app.use(passport.initialize());
            app.use(passport.session());
        },
        registerRoutes: function() {
            app.post('/auth/local',
                passport.authenticate('local', { failureRedirect: '/login', failureMessage: 'Incorrect username or password' }),
                function(req, res) {
                    res.redirect('/account');
                }
            );
        }
    };
}


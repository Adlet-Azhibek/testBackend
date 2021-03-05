require('dotenv').config();
const argon2 = require('argon2');
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const httpsLocalhost = require("https-localhost")();
const https = require('https');
const app = express();
var fs = require('fs');
var cors = require('cors');
const PORT = 8007;
const fileUpload = require('express-fileupload');

const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const accessTokenSecret = process.env.accessTokenSecret;
const refreshTokenSecret = process.env.refreshTokenSecret;

var mysql = require('mysql');
var pool = mysql.createPool({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'erp.aero'
    });

httpsLocalhost.getCerts().then((certs) => {
    const httpsServer = https.createServer(certs, app).listen(PORT);
    console.log('gateway run on port ' + PORT);
})
/*
app.listen(PORT, () => {
console.log('gateway run on port ' + PORT);
});
 */
app.use(helmet());
app.use(cookieParser());
app.use(bodyParser.urlencoded({
        extended: true
    }));
app.use(bodyParser.json());

app.use(cors()); //CORS-enabled for all origins

app.use(fileUpload({
        limits: {
            fileSize: 50 * 1024 * 1024
        } //50mb
    }));

app.post('/signin', cors(), (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    pool.query('SELECT * from users where email = ?', [email], async function (error, results, fields) {
        if (error) {
            //throw error;
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            var user = results[0];
            if (!user) {
                res.status(500).send({
                    status: 'error',
                    value: 'not registered'
                });
            } else {
                try {
                    var hashedPassword = await argon2.hash(password);
                } catch (errHash) {
                    res.status(500).send({
                        status: 'error',
                        value: errHash
                    });
                    return;
                }
                var passwordFromDB = user.password;
                delete user.password;
                try {
                    if (await argon2.verify(passwordFromDB, password)) { //пароль введен правильно
                        generateTokenPair(user, (err2, tokens) => {
                            if (err2) {
                                res.status(500).send({
                                    status: 'error',
                                    value: err2
                                });
                            } else {
                                var accessToken = tokens.accessToken;
                                var refreshToken = tokens.refreshToken;
                                pool.query('insert into tokens (accessToken, refreshToken, userId ) values (?, ?, ?)', [accessToken, refreshToken, user.id], async function (err4, results, fields) {
                                    if (err4) {
                                        res.status(500).send({
                                            status: 'error',
                                            value: err4
                                        });
                                    } else {
                                        res.cookie('refreshToken', refreshToken, { //записываем в куки
                                            expires: false,
                                            httpOnly: true,
                                            domain: 'localhost:' + PORT,
                                            //domain: '/',
                                            path: '/auth',
                                            secure: true
                                        });
                                        res.status(200).send({
                                            status: 'success',
                                            value: {
                                                accessToken: 'Bearer ' + accessToken,
                                                refreshToken: refreshToken
                                            }
                                        });
                                    }
                                })
                            }
                        });
                    } else {
                        res.status(500).send({
                            status: 'success',
                            value: 'wrong credentials'
                        });
                    }
                } catch (errVerify) {
                    res.status(500).send({
                        status: 'error',
                        value: errVerify
                    });
                }
            }
        }
    })
});

app.post('/signin/new_token', async(req, res) => {
    var header = req.headers['authorization'];
    if (header) {
        var bearer = header.split(' ');
        var accessTokenCurrent = bearer[1];
    }
    var refreshTokenCurrent = req.cookies.refreshToken;
    if (accessTokenCurrent && refreshTokenCurrent) {
        pool.query('select * from tokens where accessToken= ? and refreshToken = ?', [accessTokenCurrent, refreshTokenCurrent], function (err0, results, fields) {
            if (err0) {
                res.status(500).send({ //нужно ли перенаправить на станичку логина?
                    status: 'error',
                    value: err0
                });
            } else {
                var row = results[0];
                if (!row) { //нужно ли перенаправить на станичку логина?
                    res.status(500).send({
                        status: 'error',
                        value: 'not correct tokens pair'
                    });
                } else {
                    if (row.isBlocked) { //нужно ли перенаправить на станичку логина?
                        res.status(500).send({
                            status: 'error',
                            value: 'tokens are blocked'
                        });
                    } else {
                        //дать новую пару токенов юзеру
                        //только если его рефреш токен еще действительный
                        jwt.verify(refreshTokenCurrent, refreshTokenSecret, {}, (err, jwt_payload) => {
                            if (err) {
                                res.status(401).send({
                                    status: 'error',
                                    value: err
                                });
                            } else {
                                pool.query('select * from users where id = ?', [jwt_payload.sub], function (err1, results, fields) {
                                    var user = results[0];
                                    if (err1) {
                                        res.status(500).send({
                                            status: 'error',
                                            value: err1
                                        });
                                    }
                                    if (user) {
                                        delete user.password; //пароль не должен быть в токене
                                        generateTokenPair(user, (err2, tokens) => {
                                            if (err2) {
                                                res.status(500).send({
                                                    status: 'error',
                                                    value: err2
                                                });
                                            } else {
                                                var accessTokenNew = tokens.accessToken;
                                                var refreshTokenNew = tokens.refreshToken;
                                                pool.query('insert into tokens (accessToken, refreshToken, userId ) values (?, ?, ?)', [accessTokenNew, refreshTokenNew, user.id], async function (err4, results, fields) {
                                                    if (err4) {
                                                        res.status(500).send({
                                                            status: 'error',
                                                            value: err4
                                                        });
                                                    } else {
                                                        pool.query('update tokens set isBlocked=true where accessToken = ? and refreshToken = ?', [accessTokenCurrent, refreshTokenCurrent, user.id], async function (err5, results, fields) {
                                                            if (err5) {
                                                                res.status(500).send({
                                                                    status: 'error',
                                                                    value: err5
                                                                });
                                                            } else {
                                                                res.cookie('refreshToken', refreshTokenNew, { //записываем в куки
                                                                    expires: false,
                                                                    httpOnly: true,
                                                                    domain: 'localhost:' + PORT,
                                                                    //domain: '/',
                                                                    path: '/auth',
                                                                    secure: true
                                                                });
                                                                res.status(200).send({
                                                                    status: 'success',
                                                                    value: {
                                                                        accessToken: 'Bearer ' + accessTokenNew,
                                                                        refreshToken: refreshTokenNew
                                                                    }
                                                                });
                                                            }
                                                        })
                                                    }
                                                })
                                            }
                                        })
                                    } else {
                                        res.status(500).send({
                                            status: 'error',
                                            value: 'user not found'
                                        });
                                    }
                                })

                            }
                        })
                    }

                }
            }
        });
    } else {
        res.status(401).send({ //нужно ли перенаправить на станичку логина?
            status: 'error',
            value: 'please, log in'
        });
    }
});

app.post('/signup', async(req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    pool.query('select * from users where email = ?', [email], async function (err1, results, fields) {
        if (err1) {
            res.status(401).send({
                status: 'error',
                value: err1
            });
        } else {
            if (results[0] && results[0].id) {
                res.status(401).send({
                    status: 'error',
                    value: 'already registered'
                });
            } else {
                try {
                    var hashedPassword = await argon2.hash(password);
                } catch (errHash) {
                    res.status(500).send({
                        status: 'error',
                        value: errHash
                    });
                    return;
                }
                pool.query('insert into users (email, password) values (?, ?)', [email, hashedPassword], function (err2, results2, fields) {
                    if (err2) {
                        res.status(401).send({
                            status: 'error',
                            value: err2
                        });
                    } else {
                        var user = {
                            id: results2.insertId
                        }
                        generateTokenPair(user, (err2, tokens) => {
                            if (err2) {
                                res.status(500).send({
                                    status: 'error',
                                    value: err2
                                });
                            } else {
                                var accessToken = tokens.accessToken;
                                var refreshToken = tokens.refreshToken;
                                pool.query('insert into tokens (accessToken, refreshToken, userId ) values (?, ?, ?)', [accessToken, refreshToken, user.id], async function (err4, results, fields) {
                                    if (err4) {
                                        res.status(500).send({
                                            status: 'error',
                                            value: err4
                                        });
                                    } else {
                                        res.cookie('refreshToken', refreshToken, { //записываем в куки
                                            expires: false,
                                            httpOnly: true,
                                            domain: 'localhost:' + PORT,
                                            //domain: '/',
                                            path: '/auth',
                                            secure: true
                                        });
                                        res.status(200).send({
                                            status: 'success',
                                            value: {
                                                accessToken: 'Bearer ' + accessToken,
                                                refreshToken: refreshToken
                                            }
                                        });
                                    }
                                })
                            }
                        });
                    }
                })
            }
        }
    })
});

app.post('/file/upload', checkAccessToken, async(req, res) => {
    //рекомендуется загружать файлы с названием на латинице,
    //на кириллице очень странные символы отправляет Postman, из-за этого не получается загрузить файл
    if (!req.files || Object.keys(req.files).length == 0) {
        return res.status(400).send('No files were uploaded.');
    }
    var file = req.files.file;
    uploadFile(file, function (error, result) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            res.status(200).send({
                status: 'success',
                value: 'success'
            });
        }
    });

});

app.get('/file/list', checkAccessToken, async(req, res) => {
    var page = req.body.page || 1;
    var list_size = req.body.list_size || 10;
    pool.query('select * from files order by inserted_at desc', function (error, results, fields) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            var start = list_size * (page - 1); //last index of previous page, //0 if it is first page
            var end = list_size;
            res.status(200).send({
                status: 'success',
                value: results.splice(start, end)
            });
        }
    });
});

app.delete('/file/delete/:id', checkAccessToken, async(req, res) => {
    var id = req.params.id;
    pool.query('select * from files where id = ?', [id], async function (error, results, fields) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            if (results[0] && results[0].location) {
                removeFile(results, function (err, result) {
                    if (err) {
                        res.status(500).send({
                            status: 'error',
                            value: err
                        });
                    } else {
                        res.status(200).send({
                            status: 'success',
                            value: 'success'
                        });
                    }
                });
            } else {
                res.status(500).send({
                    status: 'error',
                    value: 'cannot find file by id in DB'
                });
            }
        }
    });
});

function removeFile(results, callback) {
    fs.unlink(results[0].location, function (err) {
        if (err) {
            callback(err, null);
        } else {
            pool.query('delete from files where id = ?', [results[0].id], function (error2, results, fields) {
                if (error2) {
                    callback(error2, null);
                } else {
                    callback(null, {});
                }
            });
        }
    });
}

function uploadFile(file, callback) {
    var fileLink = __dirname + '/files/' + file.name;
    var extension = get_file_extension(file.name);
    fs.access(fileLink, (err) => {
        if (err) { //файла с таким именем нет, можно загружать
            fs.writeFile(fileLink, file.data, function (err, result) { //создание файла на сервере
                if (err) {
                    callback(err, null);
                } else {
                    pool.query('insert into files (fileName, extension, mimeType, sizeInBytes, location) values (?, ?, ?, ?, ?)', [file.name, extension, file.mimetype, file.size, fileLink], function (error, results, fields) {
                        if (error) {
                            callback(error, null);
                        } else {
                            callback(null, {});
                        }
                    });
                }
            });
        } else {
            callback('file with same name is already uploaded', null);
        }
    });
}

app.get('/file/:id', checkAccessToken, async(req, res) => {
    var id = req.params.id;
    pool.query('select * from files where id = ?', [id], async function (error, results, fields) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            if (results[0]) {
                res.status(200).send({
                    status: 'success',
                    value: results[0]
                });
            } else {
                res.status(500).send({
                    status: 'error',
                    value: 'cannot find file by id in DB'
                });
            }
        }
    });
});

app.get('/file/download/:id', checkAccessToken, async(req, res) => {
    var id = req.params.id;
    pool.query('select * from files where id = ?', [id], async function (error, results, fields) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            if (results[0] && results[0].location) {
                res.download(results[0].location);
            } else {
                res.status(500).send({
                    status: 'error',
                    value: 'cannot find file by id in DB'
                });
            }
        }
    });
    //res.send(id);
});

app.put('/file/update/:id', checkAccessToken, async(req, res) => {
    var id = req.params.id;
    if (!req.files || Object.keys(req.files).length == 0) {
        return res.status(400).send('No files were uploaded.');
    }
    var file = req.files.file;
    pool.query('select * from files where id = ?', [id], async function (error, results, fields) {
        if (error) {
            res.status(500).send({
                status: 'error',
                value: error
            });
        } else {
            if (results[0] && results[0].location) {
                removeFile(results, function (err, result) { //удаляем старый файл
                    if (err) {
                        res.status(500).send({
                            status: 'error',
                            value: err
                        });
                    } else {
                        uploadFile(file, function (error, result) { //загружаем новый файл
                            if (error) {
                                res.status(500).send({
                                    status: 'error',
                                    value: error
                                });
                            } else {
                                res.status(200).send({
                                    status: 'success',
                                    value: 'success'
                                });
                            }
                        });

                    }
                });
            } else {
                res.status(500).send({
                    status: 'error',
                    value: 'cannot find file by id in DB'
                });
            }
        }
    });
});

app.get('/info', checkAccessToken, async(req, res) => {
    pool.query('select email from users where id = ?', [req.userId], async function (err1, results, fields) {
        if (err1) {
            res.status(401).send({
                status: 'error',
                value: err1
            });
        } else {
            res.status(200).send({
                status: 'success',
                value: results[0]
            });
        }
    })

});

app.get('/logout', async(req, res) => {
    var header = req.headers['authorization'];
    if (header) {
        var bearer = header.split(' ');
        var accessTokenCurrent = bearer[1];
    }
    var refreshTokenCurrent = req.cookies.refreshToken;
    if (accessTokenCurrent && refreshTokenCurrent) {
        pool.query('update tokens set isBlocked=true where accessToken = ? and refreshToken = ?', [accessTokenCurrent, refreshTokenCurrent, user.id], async function (err5, results, fields) {
            if (err5) {
                res.status(500).send({
                    status: 'error',
                    value: err5
                });
            } else {
                res.clearCookie('refreshToken');
                res.status(200).send({
                    status: 'success',
                    value: 'logged out'
                });
            }
        })

    } else {
        res.status(401).send({
            status: 'error',
            value: 'you are not logged in'
        });
    }

});

function checkAccessToken(req, res, next) {
    var header = req.headers['authorization'];
    if (typeof header !== 'undefined') {
        var bearer = header.split(' ');
        var accessToken = bearer[1];
        jwt.verify(accessToken, accessTokenSecret, {}, (err, jwt_payload) => {
            if (err) {
                res.status(401).send({
                    status: 'error',
                    value: err
                });
            } else {
                pool.query('select * from tokens where accessToken = ? and userId = ?', [accessToken, jwt_payload.sub], function (err1, results, fields) {
                    if (err1) {
                        res.status(401).send({
                            status: 'error',
                            value: err1
                        });
                    } else {
                        if (!results || !results[0]) {
                            res.status(401).send({
                                status: 'error',
                                value: 'token is not found'
                            });
                        } else {
                            if (results[0].isBlocked) {
                                res.status(401).send({
                                    status: 'error',
                                    value: 'token is blocked'
                                });
                            } else {
                                req.userId = jwt_payload.sub;
                                next()
                            }

                        }
                    }
                })
            }
        })
    } else {
        //If header is undefined return Forbidden (403)
        res.sendStatus(403)
    }

}

function generateTokenPair(user, callback) {
    generateAccessToken(user, (err2, accessToken) => {
        if (err2) {
            callback(err2, {});
        } else {
            generateRefreshToken(user, (err3, refreshToken) => {
                if (err3) {
                    callback(err3, {});
                } else {
                    callback(null, {
                        accessToken: accessToken,
                        refreshToken: refreshToken
                    })
                }
            })
        }
    })
}

function generateRefreshToken(user, callback) {
    var tokenParams = {
        expiresIn: '1d'
    };
    const payload = {
        sub: user.id
    };
    jwt.sign(payload, refreshTokenSecret, tokenParams, (err2, token) => {
        callback(err2, token);
    })
}

function generateAccessToken(user, callback) {
    var tokenParams = {
        expiresIn: '10m'
    };
    const payload = {
        sub: user.id
    };
    jwt.sign(payload, accessTokenSecret, tokenParams, (err2, token) => {
        callback(err2, token);
    })
}

function get_file_extension(filename) {
    return (/[.]/.exec(filename)) ? /[^.]+$/.exec(filename) : undefined;
}

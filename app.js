const express = require('express')
const app = new express()
var bodyParser = require('body-parser')
var multer = require('multer')
const {
  v1: uuidv1
} = require('uuid');
const jwt = require("jsonwebtoken")
var mysql = require('mysql');
var os = require("os")
var cors = require('cors');

//创建密钥
const secret = "mclocidgreat";

// 创建一个数据库连接池
let pool = mysql.createPool({
  host: 'localhost',
  port: '3306',
  database: 'account',
  user: 'root',
  password: 'root',
  connectionLimit: 100 //连接池大小
});

//定义创建数据库链接函数
const addContent = function (sql, sqlParams, req, res, callback) {
  //使用
  pool.getConnection((err, connection) => {
    if (err) {
      console.log("连接失败：" + err);
      res.json({
        code: 50000,
        msg: "服务器内部错误！请联系管理员。",
      })
    } else {
      connection.query(sql, sqlParams, function (err, result) {
        if (err) {
          console.log('[ERROR] - ', err.message);
          res.json({
            code: 50000,
            msg: "服务器内部错误！请联系管理员。",
          })
          return;
        }
        callback(result);
      });
      //释放
      connection.release();
    }
  });
};

//自定义token验证函数
const checkToken = function (req, res, uuid, token, callback) {
  if (uuid) {
    if (token) {
      jwt.verify(token, secret, function (err, decoded) {
        if (err) {
          res.json({
            code: 40004,
            msg: "token非法！",
            data: err,
          })
        } else if (decoded) {
          if (decoded.uuid == uuid) {
            if (decoded.exp >= Date.now()) {
              callback(decoded);
            } else {
              res.json({
                code: 40005,
                msg: "token过期，请重新登陆。",
              })
            }
          } else {
            res.json({
              code: 40006,
              msg: "token校验失败，请检查uuid是否正确！",
            })
          }
        }
      })
    } else {
      res.json({
        code: 40002,
        msg: "非法请求，请传入token！",
      })
    }
  } else {
    res.json({
      code: 40003,
      msg: "非法请求，请传入uuid！",
    })
  }
}

/* 图片上传 start */
//上传路径、文件名
var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads') //使用uploads文件夹存放图片
  },
  filename: function (req, file, cb) {
    //提取拓展名
    var singfileArray = file.originalname.split('.');
    var fileExtension = singfileArray[singfileArray.length - 1];
    cb(null, file.fieldname + '-' + Date.now() + '.' + fileExtension)
  }
})

//限制上传文件大小及数量
var limits = {
  //限制文件大小1000kb
  fileSize: 1000 * 1000,
  //限制文件数量
  files: 1
}

//过滤器：限制上传文件类型
var fileFilter = function (req, file, cb) {
  // 限制文件上传类型，仅可上传png格式图片
  if (file.mimetype == 'image/png') {
    cb(null, true)
  } else if (file.mimetype == 'image/jpeg') {
    cb(null, true)
  } else {
    cb(null, false)
    // 如果有问题，你可以总是这样发送一个错误:
    cb(new Error('I don\'t have a clue!'))
  }
}

var upload = multer({
  limits: limits,
  storage: storage,
  fileFilter: fileFilter,
}).single('avatar')
/* 图片上传 end */

//跨域
app.use(cors());

// 静态托管
app.use('/uploads', express.static('uploads'))

// 解析 application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({
  extended: false
}))
// 解析 application/json
app.use(bodyParser.json())

//服务端渲染，模板资源目录、使用ejs模板引擎
app.set('views', 'views');
app.set('views engine', 'ejs');

/* ------------------------------------- 页面 -------------------------------------*/

app.get('/', (request, response) => {
  response.render('start.ejs'); // .ejs 可以省略
});

/* ------------------------------------- 接口 -------------------------------------*/

// 服务状态
app.get('/servicestatus', function (req, res) {
  let serviceTime = process.uptime().toFixed(2);
  let rss = (process.memoryUsage().rss / 1024 / 1024).toFixed(2) + ' MB';
  let heapTotal = (process.memoryUsage().heapTotal / 1024 / 1024).toFixed(2) + ' MB';
  let heapUsed = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2) + ' MB';
  let external = (process.memoryUsage().external / 1024 / 1024).toFixed(2) + ' MB';
  let arrayBuffers = (process.memoryUsage().arrayBuffers / 1024 / 1024).toFixed(2) + ' MB';
  let serverLoad = os.loadavg();
  let serverTotalMemory = (os.totalmem() / 1024 / 1024).toFixed(2);
  let serverFreeMemory = (os.freemem() / 1024 / 1024).toFixed(2);

  res.json({
    code: 20000,
    msg: '服务状态',
    data: {
      serviceTime: serviceTime,
      serviceMemory: [{
          name: 'rss',
          data: rss
        },
        {
          name: 'heapTotal',
          data: heapTotal
        },
        {
          name: 'heapUsed',
          data: heapUsed
        },
        {
          name: 'external',
          data: external
        },
        {
          name: 'arrayBuffers',
          data: arrayBuffers
        }
      ],
      serverLoad: serverLoad,
      serverMemory: {
        serverTotalMemory,
        serverFreeMemory
      }
    }
  })
})

// 图片上传
app.post('/uploadavatar', function (req, res) {
  console.log(req)
  let token = req.query.token;
  let uuid = req.query.uuid;
  checkToken(req, res, uuid, token, (decoded) => {
    upload(req, res, function (err) {
      if (err instanceof multer.MulterError) {
        // 发生错误
        res.json({
          code: 40008,
          msg: '图片上传失败',
          data: err
        })
        return
      } else if (err) {
        // 发生错误
        res.json({
          code: 40007,
          msg: '图片上传失败',
          data: err
        })
      } else {
        // 一切都好
        res.json({
          code: 20000,
          msg: '图片上传成功',
          path: req.file.path
        })
      }
    })
  })
})

// 检查用户名
app.post('/checkusername', (req, res) => {
  let username = req.body.username;
  let retrieveSql = `SELECT * FROM account WHERE username='${username}'`;
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      res.json({
        code: 40000,
        msg: '用户名重复',
      })
    } else {
      res.json({
        code: 20000,
        msg: '用户名可用',
      })
    }
  })
})

//用户注册
app.post('/register', (req, res) => {
  let username = req.body.username
  let password = req.body.password
  let uuid = uuidv1();
  let retrieveSql = `SELECT * FROM account WHERE username='${username}'`;
  let createSql = 'INSERT INTO account(Id,uuid,username,password,avatarurl,description,other) VALUES(0,?,?,?,?,?,?)';
  let createSqlParams = [uuid, username, password, '', '', ''];
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      res.json({
        code: 40000,
        msg: '注册失败，用户名重复！',
      })
    } else {
      addContent(createSql, createSqlParams, req, res, (result) => {
        res.json({
          code: 20000,
          msg: '注册成功',
          data: {
            username: username,
            uuid: uuid
          }
        })
      })
    }
  })
})

//用户登录
//查看是否有对应的用户名密码组合
app.post('/login', (req, res) => {
  let username = req.body.username
  let password = req.body.password
  let retrieveSql = `SELECT * FROM account WHERE username='${username}' AND password='${password}'`;
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      let uuid = result[0].uuid;
      let issuedAt = Date.now();
      let expirationTime = Date.now() + (1000 * 60 * 60 * 24); //过期时间24小时
      let payload = {
        username: username,
        uuid: uuid,
        iat: issuedAt, //发行时间
        exp: expirationTime, //过期时间
      }
      let token = jwt.sign(payload, secret)
      res.json({
        code: 20000,
        msg: "登录成功",
        data: {
          username: result[0].username,
          uuid: result[0].uuid,
          token: token,
        },
      })
    } else {
      res.json({
        code: 40001,
        msg: "登录失败，用户名或密码错误",
      })
    }
  })
})

//获取单个用户信息
app.post('/getuser', (req, res) => {
  let token = req.body.token;
  let uuid = req.body.uuid;
  checkToken(req, res, uuid, token, (decoded) => {
    let retrieveSql = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql, null, req, res, (result) => {
      if (result.length > 0) {
        res.json({
          code: 20000,
          msg: "获取成功",
          data: result
        })
      } else {
        res.json({
          code: 50000,
          msg: "获取失败"
        })
      }
    })
  })
})

// 修改用户信息
app.post('/updateuser', (req, res) => {
  let token = req.body.token;
  let uuid = req.body.uuid;
  checkToken(req, res, uuid, token, (decoded) => {
    let username = req.body.username;
    let password = req.body.password;
    let avatarurl = req.body.avatarurl;
    let description = req.body.description;
    let other = req.body.other;
    let retrieveSql = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql, null, req, res, (result) => {
      if (result.length > 0) {
        if (!username) {
          username = result[0].username
        }
        if (!password) {
          password = result[0].password
        }
        if (!avatarurl) {
          avatarurl = result[0].avatarurl
        }
        if (!description) {
          description = result[0].description
        }
        if (!other) {
          other = result[0].other
        }
        let updateSql = 'UPDATE account SET username = ?,password = ?,avatarurl = ?,description = ?,other = ? WHERE uuid = ?';
        let updateSqlParams = [username, password, avatarurl, description, other, uuid];
        addContent(updateSql, updateSqlParams, req, res, (result) => {
          if (result.affectedRows > 0) {
            if (result.changedRows > 0) {
              res.json({
                code: 20000,
                msg: "修改成功",
                data: result
              })
            } else if (result.changedRows == 0) {
              res.json({
                code: 20000,
                msg: "修改成功，但要修改的数据与原数据相同",
                data: result
              })
            }
          } else {
            res.json({
              code: 40000,
              msg: "修改失败",
              data: result
            })
          }
        })
      } else {
        res.json({
          code: 40000,
          msg: "uuid不存在",
        })
      }
    })
  })
})

//注销用户
app.post('/cancelaccount', (req, res) => {
  let token = req.body.token;
  let uuid = req.body.uuid;
  checkToken(req, res, uuid, token, (decoded) => {
    let username = req.body.username;
    let password = req.body.password;
    let retrieveSql = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql, null, req, res, (result) => {
      if (result.length > 0) {
        if (username == result[0].username && password == result[0].password) {
          let deleteSql = `DELETE FROM account where uuid='${uuid}'`;
          addContent(deleteSql, null, req, res, (result) => {
            if (result.affectedRows > 0) {
              res.json({
                code: 20000,
                msg: "注销成功",
                data: result
              })
            } else {
              console.log('[ERROR] - ', result)
              res.json({
                code: 50000,
                msg: "注销失败，请联系管理员。",
                data: result
              })
            }
          })
        } else {
          res.json({
            code: 40000,
            msg: "用户名或密码不正确",
          })
        }
      } else {
        res.json({
          code: 40000,
          msg: "uuid不存在",
        })
      }
    })
  })
})

// 获取全部用户列表《debug》 仅超级用户可用
app.post('/getalluser', (req, res) => {
  let token = req.body.token;
  let uuid = req.body.uuid;
  checkToken(req, res, uuid, token, (decoded) => {
    console.log(decoded)
    if (decoded.username == "admin") {
      let retrieveSql = `SELECT * FROM account`;
      addContent(retrieveSql, null, req, res, (result) => {
        res.json({
          code: 20000,
          msg: "获取全部用户列表成功",
          data: result
        })
      })
    } else {
      res.json({
        code: 40000,
        msg: "您没有权限查看此内容！大侠手下留情╥﹏╥...",
      })
    }
  })
})

app.listen(8888, '127.0.0.1')
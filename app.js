const express = require("express");
const app = new express();
var bodyParser = require("body-parser");
var multer = require("multer");
const { v1: uuidv1 } = require("uuid");
const jwt = require("jsonwebtoken");
var mysql = require("mysql");
var os = require("os");
var cors = require("cors");
const Apicount = require("./model/count");

//创建密钥
const secret = "mclocidgreat";

// 创建一个数据库连接池
let pool = mysql.createPool({
  host: "localhost",
  port: "3306",
  database: "account",
  user: "root",
  password: "root",
  connectionLimit: 100, //连接池大小
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
      });
    } else {
      connection.query(sql, sqlParams, function (err, result) {
        if (err) {
          console.log("[ERROR] - ", err.message);
          res.json({
            code: 50000,
            msg: "服务器内部错误！请联系管理员。",
          });
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
          });
        } else if (decoded) {
          if (decoded.uuid == uuid) {
            if (decoded.exp >= Date.now()) {
              callback(decoded);
            } else {
              res.json({
                code: 40005,
                msg: "token过期，请重新登陆。",
              });
            }
          } else {
            res.json({
              code: 40006,
              msg: "token校验失败，请检查uuid是否正确！",
            });
          }
        }
      });
    } else {
      res.json({
        code: 40002,
        msg: "非法请求，请传入token！",
      });
    }
  } else {
    res.json({
      code: 40003,
      msg: "非法请求，请传入uuid！",
    });
  }
};

/* 图片上传 start */
//上传路径、文件名
var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads"); //使用uploads文件夹存放图片
  },
  filename: function (req, file, cb) {
    //提取拓展名
    var singfileArray = file.originalname.split(".");
    var fileExtension = singfileArray[singfileArray.length - 1];
    cb(null, file.fieldname + "-" + Date.now() + "." + fileExtension);
  },
});

//限制上传文件大小及数量
var limits = {
  //限制文件大小1000kb
  fileSize: 1000 * 1000,
  //限制文件数量
  files: 1,
};

//过滤器：限制上传文件类型
var fileFilter = function (req, file, cb) {
  // 限制文件上传类型，仅可上传png格式图片
  if (file.mimetype == "image/png") {
    cb(null, true);
  } else if (file.mimetype == "image/jpeg") {
    cb(null, true);
  } else {
    cb(null, false);
    // 如果有问题，你可以总是这样发送一个错误:
    cb(new Error("I don't have a clue!"));
  }
};

var upload = multer({
  limits: limits,
  storage: storage,
  fileFilter: fileFilter,
}).single("avatar");
/* 图片上传 end */

//跨域
app.use(cors());

// 静态托管
app.use("/uploads", express.static("uploads"));
app.use("/adminassets", express.static("views/admin"));

// 解析 application/x-www-form-urlencoded
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
// 解析 application/json
app.use(bodyParser.json());

//服务端渲染，模板资源目录、使用ejs模板引擎
app.set("views", "views");
app.set("views engine", "ejs");

/* ------------------------------------- 页面 -------------------------------------*/

app.get("/", (request, response) => {
  response.render("start.ejs"); // .ejs 可以省略
});

app.get("/admin", (request, response) => {
  response.render("./admin/index.ejs"); // .ejs 可以省略
});

/* ------------------------------------- 接口 -------------------------------------*/

// 服务状态 0
app.get("/servicestatus", function (req, res) {
  let serviceTime = process.uptime().toFixed(2);
  let rss = (process.memoryUsage().rss / 1024 / 1024).toFixed(2) + " MB";
  let heapTotal =
    (process.memoryUsage().heapTotal / 1024 / 1024).toFixed(2) + " MB";
  let heapUsed =
    (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2) + " MB";
  let external =
    (process.memoryUsage().external / 1024 / 1024).toFixed(2) + " MB";
  let arrayBuffers =
    (process.memoryUsage().arrayBuffers / 1024 / 1024).toFixed(2) + " MB";
  let serverLoad = os.loadavg();
  let serverTotalMemory = (os.totalmem() / 1024 / 1024).toFixed(2);
  let serverFreeMemory = (os.freemem() / 1024 / 1024).toFixed(2);
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count0 = mon[0].count0 + 1;
    let count = mon[0].count;
    Apicount.findByIdAndUpdate(id, {
      count0: count0,
    }).then((mon) => {
      res.json({
        code: 20000,
        msg: "服务状态",
        data: {
          serviceTime: serviceTime,
          serviceMemory: [
            {
              name: "rss",
              data: rss,
            },
            {
              name: "heapTotal",
              data: heapTotal,
            },
            {
              name: "heapUsed",
              data: heapUsed,
            },
            {
              name: "external",
              data: external,
            },
            {
              name: "arrayBuffers",
              data: arrayBuffers,
            },
          ],
          serverLoad: serverLoad,
          serverMemory: {
            serverTotalMemory,
            serverFreeMemory,
          },
          count: count,
        },
      });
    });
  });
});

// 图片上传 1
app.post("/uploadavatar", function (req, res) {
  let token = req.headers.token;
  let uuid = req.headers.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count1 = mon[0].count1 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count1: count1,
      count: count,
    }).then();
  });
  checkToken(req, res, uuid, token, (decoded) => {
    upload(req, res, function (err) {
      if (err instanceof multer.MulterError) {
        // 发生错误
        res.json({
          code: 40008,
          msg: "图片上传失败",
          data: err,
        });
        return;
      } else if (err) {
        // 发生错误
        res.json({
          code: 40007,
          msg: "图片上传失败",
          data: err,
        });
      } else {
        // 一切都好
        res.json({
          code: 20000,
          msg: "图片上传成功",
          path: req.file.path,
        });
      }
    });
  });
});

// 检查用户名 2
app.post("/checkusername", (req, res) => {
  let username = req.body.username;
  let retrieveSql = `SELECT * FROM account WHERE username='${username}'`;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count2 = mon[0].count2 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count2: count2,
      count: count,
    }).then();
  });
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      res.json({
        code: 40000,
        msg: "用户名重复",
      });
    } else {
      res.json({
        code: 20000,
        msg: "用户名可用",
      });
    }
  });
});

//用户注册 3
app.post("/register", (req, res) => {
  let username = req.body.username;
  let password = req.body.password;
  let uuid = uuidv1();
  let retrieveSql = `SELECT * FROM account WHERE username='${username}'`;
  let createSql =
    "INSERT INTO account(Id,uuid,username,password,avatarurl,description,other) VALUES(0,?,?,?,?,?,?)";
  let createSqlParams = [
    uuid,
    username,
    password,
    "https://account.api.mcloc.cn/uploads/DefaultAvatar.jpg",
    "",
    "",
  ];
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count3 = mon[0].count3 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count3: count3,
      count: count,
    }).then();
  });
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      res.json({
        code: 40000,
        msg: "注册失败，用户名重复！",
      });
    } else {
      addContent(createSql, createSqlParams, req, res, (result) => {
        res.json({
          code: 20000,
          msg: "注册成功",
          data: {
            username: username,
            uuid: uuid,
          },
        });
      });
    }
  });
});

//用户登录
//查看是否有对应的用户名密码组合 4
app.post("/login", (req, res) => {
  let username = req.body.username;
  let password = req.body.password;
  let retrieveSql = `SELECT * FROM account WHERE username='${username}' AND password='${password}'`;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count4 = mon[0].count4 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count4: count4,
      count: count,
    }).then();
  });
  addContent(retrieveSql, null, req, res, (result) => {
    if (result.length > 0) {
      let uuid = result[0].uuid;
      let issuedAt = Date.now();
      let expirationTime = Date.now() + 1000 * 60 * 60 * 24; //过期时间24小时
      let payload = {
        username: username,
        uuid: uuid,
        iat: issuedAt, //发行时间
        exp: expirationTime, //过期时间
      };
      let token = jwt.sign(payload, secret);
      res.json({
        code: 20000,
        msg: "登录成功",
        data: {
          username: result[0].username,
          uuid: result[0].uuid,
          token: token,
        },
      });
    } else {
      res.json({
        code: 40001,
        msg: "登录失败，用户名或密码错误",
      });
    }
  });
});

//获取单个用户信息 5
app.post("/getuser", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count5 = mon[0].count5 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count5: count5,
      count: count,
    }).then();
  });
  checkToken(req, res, uuid, token, (decoded) => {
    let retrieveSql = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql, null, req, res, (result) => {
      if (result.length > 0) {
        res.json({
          code: 20000,
          msg: "获取成功",
          data: result,
        });
      } else {
        res.json({
          code: 50000,
          msg: "获取失败",
        });
      }
    });
  });
});

// 修改用户信息 6
app.post("/updateuser", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count6 = mon[0].count6 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count6: count6,
      count: count,
    }).then();
  });
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
          username = result[0].username;
        }
        if (!password) {
          password = result[0].password;
        }
        if (!avatarurl) {
          avatarurl = result[0].avatarurl;
        }
        if (!description) {
          description = result[0].description;
        }
        if (!other) {
          other = result[0].other;
        }
        let updateSql =
          "UPDATE account SET username = ?,password = ?,avatarurl = ?,description = ?,other = ? WHERE uuid = ?";
        let updateSqlParams = [
          username,
          password,
          avatarurl,
          description,
          other,
          uuid,
        ];
        addContent(updateSql, updateSqlParams, req, res, (result) => {
          if (result.affectedRows > 0) {
            if (result.changedRows > 0) {
              res.json({
                code: 20000,
                msg: "修改成功",
                data: result,
              });
            } else if (result.changedRows == 0) {
              res.json({
                code: 20000,
                msg: "修改成功，但要修改的数据与原数据相同",
                data: result,
              });
            }
          } else {
            res.json({
              code: 40000,
              msg: "修改失败",
              data: result,
            });
          }
        });
      } else {
        res.json({
          code: 40000,
          msg: "uuid不存在",
        });
      }
    });
  });
});

//注销用户 7
app.post("/cancelaccount", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count7 = mon[0].count7 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count7: count7,
      count: count,
    }).then();
  });
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
                data: result,
              });
            } else {
              console.log("[ERROR] - ", result);
              res.json({
                code: 50000,
                msg: "注销失败，请联系管理员。",
                data: result,
              });
            }
          });
        } else {
          res.json({
            code: 40000,
            msg: "用户名或密码不正确",
          });
        }
      } else {
        res.json({
          code: 40000,
          msg: "uuid不存在",
        });
      }
    });
  });
});

// 获取全部用户列表 仅超级用户可用 8
app.post("/getalluser", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count8 = mon[0].count8 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count8: count8,
      count: count,
    }).then();
  });
  checkToken(req, res, uuid, token, (decoded) => {
    let retrieveSql0 = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql0, null, req, res, (result) => {
      if (result[0].roles === 1000) {
        let retrieveSql = `SELECT * FROM account`;
        addContent(retrieveSql, null, req, res, (result) => {
          res.json({
            code: 20000,
            msg: "获取全部用户列表成功",
            data: result,
          });
        });
      } else {
        res.json({
          code: 40000,
          msg: "您没有权限查看此内容！大侠手下留情╥﹏╥...",
        });
      }
    });
  });
});

// 修改用户信息 仅超级用户可用 9
app.post("/adminedituser", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count9 = mon[0].count9 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count9: count9,
      count: count,
    }).then();
  });
  checkToken(req, res, uuid, token, (decoded) => {
    let retrieveSql0 = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql0, null, req, res, (result) => {
      //检查权限
      if (result[0].roles === 1000) {
        let edituuid = req.body.edituuid;
        let retrieveSql = `SELECT * FROM account WHERE uuid='${edituuid}'`;
        addContent(retrieveSql, null, req, res, (result) => {
          let username = req.body.username; //此处以下的参数全是要修改的用户信息
          let password = req.body.password;
          let roles = req.body.roles;
          let avatarurl = req.body.avatarurl;
          let description = req.body.description;
          let other = req.body.other;
          if (result.length > 0) {
            if (!username) {
              username = result[0].username;
            }
            if (!password) {
              password = result[0].password;
            }
            if (uuid == edituuid) {
              // 如果被修改的是超级管理员
              if (roles != 1000) {
                // 超级管理员权限永远为1000
                roles = 1000;
              }
            } else {
              // 如果被修改的是普通用户
              if (roles > 100) {
                //权限禁止提升至超级管理员级别
                roles = 100;
              }
              if (!roles) {
                // 如果没有填写权限，则权限仍保持原样
                roles = result[0].roles;
              }
            }
            if (!avatarurl) {
              avatarurl = result[0].avatarurl;
            }
            if (!description) {
              description = result[0].description;
            }
            if (!other) {
              other = result[0].other;
            }
            let updateSql =
              "UPDATE account SET username = ?,password = ?,roles = ?,avatarurl = ?,description = ?,other = ? WHERE uuid = ?";
            let updateSqlParams = [
              username,
              password,
              roles,
              avatarurl,
              description,
              other,
              edituuid,
            ];
            addContent(updateSql, updateSqlParams, req, res, (result) => {
              if (result.affectedRows > 0) {
                if (result.changedRows > 0) {
                  res.json({
                    code: 20000,
                    msg: "修改成功",
                    data: result,
                  });
                } else if (result.changedRows == 0) {
                  res.json({
                    code: 20000,
                    msg: "修改成功，但要修改的数据与原数据相同",
                    data: result,
                  });
                }
              } else {
                res.json({
                  code: 40000,
                  msg: "修改失败",
                  data: result,
                });
              }
            });
          } else {
            res.json({
              code: 40000,
              msg: "edituuid不存在",
            });
          }
        });
      } else {
        res.json({
          code: 40000,
          msg: "您没有权限修改此内容！大侠手下留情╥﹏╥...",
        });
      }
    });
  });
});

// 删除用户 仅超级用户可用 10
app.post("/admindeluser", (req, res) => {
  let token = req.headers.token;
  let uuid = req.body.uuid;
  let deluuid = req.body.deluuid;
  Apicount.find().then((mon) => {
    let id = mon[0]._id;
    let count10 = mon[0].count10 + 1;
    let count = mon[0].count + 1;
    Apicount.findByIdAndUpdate(id, {
      count10: count10,
      count: count,
    }).then();
  });
  if (uuid == deluuid) {
    res.json({
      code: 40000,
      msg: "此用户不可删除",
    });
    return;
  }
  checkToken(req, res, uuid, token, (decoded) => {
    let retrieveSql0 = `SELECT * FROM account WHERE uuid='${uuid}'`;
    addContent(retrieveSql0, null, req, res, (result) => {
      if (result[0].roles === 1000) {
        let deleteSql = `DELETE FROM account where uuid='${deluuid}'`;
        addContent(deleteSql, null, req, res, (result) => {
          res.json({
            code: 20000,
            msg: "删除成功",
            data: result,
          });
        });
      } else {
        res.json({
          code: 40000,
          msg: "您没有权限查看此内容！大侠手下留情╥﹏╥...",
        });
      }
    });
  });
});

app.listen(3500, "127.0.0.1");

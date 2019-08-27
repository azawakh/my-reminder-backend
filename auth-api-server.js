// モジュール参照
const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const middlewares = jsonServer.defaults();

// JSON Serverで、利用するJSONファイルを設定
const server = jsonServer.create();
const router = jsonServer.router('./books.json');

// JSONリクエスト対応
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(middlewares);

// 署名作成ワードと有効期限(1時間)
const SECRET_WORD = 'SECRET1234';
const expiresIn = '1h';

// 署名作成関数
const createToken = payload => jwt.sign(payload, SECRET_WORD, { expiresIn });

// 署名検証関数（非同期）
const verifyToken = token =>
  new Promise((resolve, reject) =>
    jwt.verify(token, SECRET_WORD, (err, decode) =>
      decode !== undefined ? resolve(decode) : reject(err)
    )
  );

// ユーザDBファイル読み込み
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));

// ログイン関数 true:ok false:ng
const isAuth = ({ email, password }) =>
  userdb.users.findIndex(
    user => user.email === email && user.password === password
  ) !== -1;

const getUser = ({ email, password }) => {
  const { users } = userdb;
  return users[
    users.findIndex(user => user.email === email && user.password === password)
  ];
};

// ログインRouter
server.post('/auth/login', (req, res) => {
  const { user } = req.body;

  // ログイン検証
  if (isAuth(user) === false) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({ status, message });
    return;
  }

  const { id, name } = getUser(user);

  // ログイン成功時に認証トークンを発行
  const access_token = createToken(user);
  res.status(200).json({ access_token, user_id: id, name });
});

// 認証が必要なRouter(ログイン以外全て)
server.use(/^(?!\/auth).*$/, async (req, res, next) => {
  // 認証ヘッダー形式検証
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(' ')[0] !== 'Bearer'
  ) {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message });
    return;
  }

  // 認証トークンの検証
  try {
    await verifyToken(req.headers.authorization.split(' ')[1]);
    next();
  } catch (err) {
    // 失効している認証トークン
    const status = 401;
    const message = 'Error access_token is revoked';
    res.status(status).json({ status, message });
  }
});

// 認証機能付きのREST APIサーバ起動
server.use(router);
server.listen(3000, () => {
  console.log('Run Auth API Server');
});

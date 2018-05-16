const functions = require('firebase-functions');

const fs = require('fs');
const express = require('express');
const session = require('express-session');
const path = require('path');
const RedisStore = require('connect-redis')(session);

const cookie = require('cookie');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const ShopifyAPIClient = require('shopify-api-node');


const SHOPIFY_APP_KEY = 'KEY_FROM_THE_APP';
const SHOPIFY_APP_SECRET = 'SECRET_FROM_THE_APP';
const SCOPES = 'read_products, write_orders, write_products';
const SHOPIFY_APP_HOST = 'https://HOST_URL.com/';

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(
  session({
    store: new RedisStore(),
    secret: SHOPIFY_APP_SECRET,
    resave: true,
    saveUninitialized: false
  })
);
app.use(cookieParser());

 const staticPath = path.resolve(__dirname, './assets');
 app.use('/assets', express.static(staticPath));

var INSTALL_URL = '';

app.get('/shopify', (req, res) => {
  const shop = req.query.shop;
  if (shop) {
    const STATE = nonce();
    const REDIRECT_URI = `${SHOPIFY_APP_HOST}shopify/callback/`; //
    INSTALL_URL = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_APP_KEY}&scope=${SCOPES}&state=${STATE}&redirect_uri=${REDIRECT_URI}`;
    res.cookie('__session', STATE);
    res.redirect(INSTALL_URL);
  } else {
    return res
      .status(400)
      .send('add ?shop=your-development-shop.myshopify.com to your request');
  }
});

app.get('/shopify/callback/', (req, res) => {
  const { shop, hmac, code, state } = req.query;
  if (!state) res.redirect(INSTALL_URL);

  const stateCookie = req.cookies.__session;
  if (state !== stateCookie) {
    return res.status(403).send('Request origin cannot be verified');
  }
  if (shop && hmac && code) {
    const map = Object.assign({}, req.query);
    delete map['signature'];
    delete map['hmac'];
    const message = querystring.stringify(map);
    const providedHmac = Buffer.from(hmac, 'utf-8');
    const generatedHash = Buffer.from(
      crypto
        .createHmac('sha256', SHOPIFY_APP_SECRET)
        .update(message)
        .digest('hex'),
      'utf-8'
    );
    let hashEquals = false;

    try {
      hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
    } catch (e) {
      hashEquals = false;
    }

    if (!hashEquals) {
      return res.status(400).send('HMAC validation failed');
    }

    const accessTokenRequestUrl = `https://${shop}/admin/oauth/access_token`;

    const accessTokenPayload = {
      client_id: SHOPIFY_APP_KEY,
      client_secret: SHOPIFY_APP_SECRET,
      code
    };

    request
      .post(accessTokenRequestUrl, { json: accessTokenPayload })
      .then(accessTokenResponse => {
        const ACCES_TOKEN = accessTokenResponse.access_token;
        res.render('app', {
          apiKey: SHOPIFY_APP_KEY,
          shop: shop,
          token: ACCES_TOKEN
        });
      })
      .catch(error => {
        res.status(error.statusCode).send(error.error.error_description);
      });
  } else {
    res.status(400).send('Required parameters missing');
  }
});

//////////////
app.use(function(req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

app.use(function(error, request, response, next) {
  response.locals.message = error.message;
  response.status(error.status || 500);
  response.render('error');
});

exports.app = functions.https.onRequest(app);

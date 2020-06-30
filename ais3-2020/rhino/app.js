const express = require('express');
const session = require('cookie-session');

let app = express();

app.use(session({secret: 'I\'m watching you.'}));

app.use('/', express.static('./'));

app.get('/flag.txt', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');

  req.session.magic = 1e-100;
  let n = req.session.magic;

  if (n && (n + 420) === 420)
    res.sendFile('/flag');
  else
    res.send('you are a sad person too');
});

app.get('*', function(req, res) {
  res.status(404).sendFile('404.html', {root: __dirname});
});

app.listen(8080, '0.0.0.0');

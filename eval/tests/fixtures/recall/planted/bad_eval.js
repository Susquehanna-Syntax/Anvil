// Planted for the candidates-per-scan control: eval of request data. Never executed.
function handler(req, res) {
  res.send(eval(req.query.expr));
}
module.exports = handler;

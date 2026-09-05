async function proxyOrigin(request) {
  const origin = request.headers.origin;
  return fetch(origin);
}

module.exports = { proxyOrigin };

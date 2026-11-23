/*
 * entra-jwt-validate.js
 * ---------------------------------------------------------------------------
 * IBM DataPower GatewayScript action: validate a Microsoft Entra ID (Azure AD)
 * access token presented as "Authorization: Bearer <jwt>".
 *
 * Flow:
 *   1. Extract bearer token from the Authorization header
 *   2. Decode JWT header, enforce alg = RS256, read "kid"
 *   3. Fetch Entra JWKS (urlopen) and select the JWK matching "kid"
 *      - if kid is not found, re-fetch once with a cache-buster (key rollover)
 *   4. Verify signature with the DataPower "jose" module
 *   5. Validate claims: exp, nbf, iss, aud, (optional) tid, scp/roles
 *   6. Publish claims to context variables / headers; reject with 401 on failure
 *
 * Place in an MPGW request rule:  Match -> GatewayScript (this file) -> ...
 * Requires: an SSL Client Profile trusting login.microsoftonline.com
 * Recommended: XML Manager Document Cache Policy for the JWKS URL (e.g. TTL 3600s)
 * ---------------------------------------------------------------------------
 */

var urlopen = require('urlopen');
var jose    = require('jose');
var hm      = require('header-metadata');
var sm      = require('service-metadata');

/* ============================ CONFIGURATION ============================ */
var CONFIG = {
    tenantId:          'YOUR-TENANT-ID-GUID',
    // Accepted audiences: App ID URI and/or client ID of the protected API
    audiences:         ['api://your-api-client-id', 'your-api-client-id'],
    // v2.0 tokens: https://login.microsoftonline.com/{tid}/v2.0
    // v1.0 tokens: https://sts.windows.net/{tid}/
    acceptV1Issuer:    true,
    sslClientProfile:  'Entra_SSLClientProfile',   // DataPower SSL client profile name
    httpTimeoutSec:    10,
    clockSkewSec:      300,
    // Optional authorization checks (leave empty arrays to skip)
    requiredScopes:    [],      // e.g. ['Orders.Read']   -> checks "scp"
    requiredRoles:     [],      // e.g. ['Orders.Admin']  -> checks "roles"
    forwardClaimHeaders: true   // add X-JWT-* headers for the backend
};

CONFIG.jwksUrl = 'https://login.microsoftonline.com/' + CONFIG.tenantId +
                 '/discovery/v2.0/keys';
CONFIG.issuers = ['https://login.microsoftonline.com/' + CONFIG.tenantId + '/v2.0'];
if (CONFIG.acceptV1Issuer) {
    CONFIG.issuers.push('https://sts.windows.net/' + CONFIG.tenantId + '/');
}

/* ============================== HELPERS ================================ */

function fail(reason, detail) {
    // Log detail internally, return generic message to client
    console.error('[entra-jwt] ' + reason + (detail ? ' :: ' + detail : ''));
    sm.setVar('var://service/error-protocol-response', '401');
    sm.setVar('var://service/error-protocol-reason-phrase', 'Unauthorized');
    hm.response.set('WWW-Authenticate',
        'Bearer error="invalid_token", error_description="' + reason + '"');
    session.reject('Unauthorized: ' + reason);
}

function b64urlDecode(str) {
    var s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    return Buffer.from(s, 'base64').toString('utf8');
}

function getBearerToken() {
    var auth = hm.current.get('Authorization');
    if (!auth) { return null; }
    var m = /^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\s*$/i.exec(auth);
    return m ? m[1] : null;
}

function fetchJwks(bustCache, callback) {
    var target = CONFIG.jwksUrl + (bustCache ? ('?_ts=' + Date.now()) : '');
    var options = {
        target:           target,
        method:           'get',
        headers:          { 'Accept': 'application/json' },
        sslClientProfile: CONFIG.sslClientProfile,
        timeout:          CONFIG.httpTimeoutSec
    };

    urlopen.open(options, function (err, response) {
        if (err) { return callback('JWKS fetch error: ' + (err.errorMessage || String(err))); }
        if (response.statusCode !== 200) {
            return callback('JWKS endpoint returned HTTP ' + response.statusCode);
        }
        response.readAsJSON(function (readErr, jwks) {
            if (readErr) { return callback('JWKS parse error: ' + readErr); }
            if (!jwks || !Array.isArray(jwks.keys)) {
                return callback('JWKS document has no "keys" array');
            }
            callback(null, jwks);
        });
    });
}

function findKey(jwks, kid) {
    for (var i = 0; i < jwks.keys.length; i++) {
        var k = jwks.keys[i];
        if (k.kid === kid && k.kty === 'RSA' && (!k.use || k.use === 'sig')) {
            // Pass a clean RSA public JWK to the jose module
            return { kty: 'RSA', kid: k.kid, use: 'sig', n: k.n, e: k.e };
        }
    }
    return null;
}

function getKeyForKid(kid, callback) {
    fetchJwks(false, function (err, jwks) {
        if (err) { return callback(err); }
        var key = findKey(jwks, kid);
        if (key) { return callback(null, key); }

        // kid not found: possible signing-key rollover and stale cache -> refetch once
        console.warn('[entra-jwt] kid ' + kid + ' not in cached JWKS, refetching');
        fetchJwks(true, function (err2, freshJwks) {
            if (err2) { return callback(err2); }
            var freshKey = findKey(freshJwks, kid);
            if (!freshKey) { return callback('No JWKS key matches kid ' + kid); }
            callback(null, freshKey);
        });
    });
}

function verifySignature(token, jwk, callback) {
    var jwsObj;
    try {
        jwsObj = jose.parse(token);
    } catch (e) {
        return callback('Unable to parse JWS: ' + e);
    }
    jwsObj.getSignatures().forEach(function (sig) { sig.setKey(jwk); });

    var verifier = jose.createJWSVerifier(jwsObj);
    verifier.validate(function (err) {
        if (err) { return callback('Signature verification failed: ' + err); }
        callback(null);
    });
}

function validateClaims(claims) {
    var now  = Math.floor(Date.now() / 1000);
    var skew = CONFIG.clockSkewSec;

    if (typeof claims.exp !== 'number') { return 'Missing exp claim'; }
    if (now > claims.exp + skew)        { return 'Token expired'; }
    if (typeof claims.nbf === 'number' && now + skew < claims.nbf) {
        return 'Token not yet valid';
    }
    if (typeof claims.iat === 'number' && claims.iat > now + skew) {
        return 'Token issued in the future';
    }

    if (CONFIG.issuers.indexOf(claims.iss) === -1) {
        return 'Invalid issuer: ' + claims.iss;
    }
    if (claims.tid && claims.tid !== CONFIG.tenantId) {
        return 'Invalid tenant: ' + claims.tid;
    }

    var aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    var audOk = aud.some(function (a) { return CONFIG.audiences.indexOf(a) !== -1; });
    if (!audOk) { return 'Invalid audience: ' + aud.join(','); }

    if (CONFIG.requiredScopes.length) {
        var scopes = (claims.scp || '').split(' ');
        var missingScope = CONFIG.requiredScopes.filter(function (s) {
            return scopes.indexOf(s) === -1;
        });
        if (missingScope.length) { return 'Missing scope(s): ' + missingScope.join(','); }
    }
    if (CONFIG.requiredRoles.length) {
        var roles = claims.roles || [];
        var missingRole = CONFIG.requiredRoles.filter(function (r) {
            return roles.indexOf(r) === -1;
        });
        if (missingRole.length) { return 'Missing role(s): ' + missingRole.join(','); }
    }
    return null;
}

function publishClaims(claims) {
    // Context variables for downstream actions (AAA, XSLT, GatewayScript)
    sm.setVar('var://context/jwt/claims',  JSON.stringify(claims));
    sm.setVar('var://context/jwt/sub',     claims.sub   || '');
    sm.setVar('var://context/jwt/oid',     claims.oid   || '');
    sm.setVar('var://context/jwt/appid',   claims.azp   || claims.appid || '');
    sm.setVar('var://context/jwt/upn',     claims.preferred_username || claims.upn || '');

    if (CONFIG.forwardClaimHeaders) {
        hm.current.set('X-JWT-Sub',   claims.sub || '');
        hm.current.set('X-JWT-OID',   claims.oid || '');
        hm.current.set('X-JWT-AppId', claims.azp || claims.appid || '');
        hm.current.set('X-JWT-User',  claims.preferred_username || claims.upn || '');
        if (claims.roles) { hm.current.set('X-JWT-Roles', claims.roles.join(',')); }
        if (claims.scp)   { hm.current.set('X-JWT-Scopes', claims.scp); }
    }
    // Do not leak the original token to the backend unless required
    // hm.current.remove('Authorization');
}

/* ================================ MAIN ================================= */

(function main() {
    var token = getBearerToken();
    if (!token) { return fail('Missing or malformed bearer token'); }

    var parts = token.split('.');
    var header, claims;
    try {
        header = JSON.parse(b64urlDecode(parts[0]));
        claims = JSON.parse(b64urlDecode(parts[1]));
    } catch (e) {
        return fail('Malformed JWT', String(e));
    }

    // Prevent alg confusion (none / HS256 with public key)
    if (header.alg !== 'RS256') { return fail('Unsupported alg', header.alg); }
    if (!header.kid)            { return fail('Missing kid in JWT header'); }

    // Microsoft Graph tokens carry a "nonce" header and are NOT meant to be
    // validated by your API - they will always fail signature verification.
    if (header.nonce) {
        return fail('Token not issued for this API', 'nonce header present (Graph token?)');
    }

    getKeyForKid(header.kid, function (keyErr, jwk) {
        if (keyErr) { return fail('Signing key not found', keyErr); }

        verifySignature(token, jwk, function (sigErr) {
            if (sigErr) { return fail('Invalid signature', sigErr); }

            var claimErr = validateClaims(claims);
            if (claimErr) { return fail(claimErr); }

            publishClaims(claims);
            console.info('[entra-jwt] token valid for sub=' + claims.sub +
                         ' aud=' + claims.aud);
            // Pass the original payload through unchanged
            session.input.readAsBuffer(function (rErr, body) {
                if (rErr) { return session.output.write(''); }
                session.output.write(body);
            });
        });
    });
})();

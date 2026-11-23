/*
 * entra-jwt-validate.js
 * ---------------------------------------------------------------------------
 * IBM DataPower GatewayScript action: validate a Microsoft Entra ID (Azure AD)
 * access token presented as "Authorization: Bearer <jwt>" and write the result
 * as an XML node set to the action's output context.
 *
 * SUCCESS output:
 *   <claims status="valid" kid="..." alg="RS256">
 *     <claim name="aud">api://my-api</claim>
 *     <claim name="iss">https://login.microsoftonline.com/{tid}/v2.0</claim>
 *     <claim name="roles" type="array">
 *       <value>Orders.Read</value>
 *       <value>Orders.Write</value>
 *     </claim>
 *     <claim name="exp" type="number">1764000000</claim>
 *     ...
 *   </claims>
 *
 * FAILURE output:
 *   <error status="invalid">
 *     <code>TOKEN_EXPIRED</code>
 *     <message>Token expired</message>
 *     <detail>...</detail>            (only when CONFIG.includeErrorDetail = true)
 *     <timestamp>2026-11-23T20:06:00.000Z</timestamp>
 *   </error>
 *
 * Flow:
 *   1. Extract bearer token from the Authorization header
 *   2. Decode JWT header, enforce alg = RS256, read "kid"
 *   3. Fetch Entra JWKS (urlopen) and select the JWK matching "kid"
 *      - if kid is not found, re-fetch once with a cache-buster (key rollover)
 *   4. Verify signature with the DataPower "jose" module
 *   5. Validate claims: exp, nbf, iat, iss, tid, aud, (optional) scp/roles
 *   6. Write <claims> or <error> XML to the output context
 *
 * Rule usage:  GatewayScript action  Input: INPUT   Output: e.g. jwtResult
 *   Downstream XSLT/GatewayScript can test  /claims  vs  /error  in that context.
 *   Context var var://context/jwt/valid is also set to "true"/"false".
 *
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
    tenantId:           'YOUR-TENANT-ID-GUID',
    // Accepted audiences: App ID URI and/or client ID of the protected API
    audiences:          ['api://your-api-client-id', 'your-api-client-id'],
    // v2.0 tokens: https://login.microsoftonline.com/{tid}/v2.0
    // v1.0 tokens: https://sts.windows.net/{tid}/
    acceptV1Issuer:     true,
    sslClientProfile:   'Entra_SSLClientProfile',   // DataPower SSL client profile name
    httpTimeoutSec:     10,
    clockSkewSec:       300,
    // Optional authorization checks (leave empty arrays to skip)
    requiredScopes:     [],      // e.g. ['Orders.Read']   -> checks "scp"
    requiredRoles:      [],      // e.g. ['Orders.Admin']  -> checks "roles"
    // Include internal diagnostic text in <error><detail>. Keep false if the
    // XML can reach external clients.
    includeErrorDetail: false,
    // true  = also call session.reject() after writing <error> (stops the rule,
    //         runs the error rule with HTTP 401)
    // false = write <error> and let the rule continue (downstream decides)
    rejectOnFailure:    false
};

CONFIG.jwksUrl = 'https://login.microsoftonline.com/' + CONFIG.tenantId +
                 '/discovery/v2.0/keys';
CONFIG.issuers = ['https://login.microsoftonline.com/' + CONFIG.tenantId + '/v2.0'];
if (CONFIG.acceptV1Issuer) {
    CONFIG.issuers.push('https://sts.windows.net/' + CONFIG.tenantId + '/');
}

/* ============================ XML HELPERS ============================== */

function xmlEscape(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;')
        // strip characters not allowed in XML 1.0
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}

function typeOf(v) {
    if (v === null) { return 'null'; }
    if (Array.isArray(v)) { return 'array'; }
    return typeof v;   // string | number | boolean | object
}

// Render a claim value. Claim names go in @name because names like
// "http://schemas.microsoft.com/..." are not valid XML element names.
function renderValue(value, indent) {
    var t = typeOf(value);
    if (t === 'array') {
        return value.map(function (item) {
            var it = typeOf(item);
            if (it === 'object' || it === 'array') {
                return indent + '<value type="' + it + '">' + '\n' +
                       renderValue(item, indent + '  ') + indent + '</value>\n';
            }
            return indent + '<value' + (it !== 'string' ? ' type="' + it + '"' : '') +
                   '>' + xmlEscape(item) + '</value>\n';
        }).join('');
    }
    if (t === 'object') {
        return Object.keys(value).map(function (k) {
            return renderClaim(k, value[k], indent);
        }).join('');
    }
    return xmlEscape(value);
}

function renderClaim(name, value, indent) {
    var t = typeOf(value);
    var typeAttr = (t === 'string') ? '' : ' type="' + t + '"';
    if (t === 'array' || t === 'object') {
        return indent + '<claim name="' + xmlEscape(name) + '"' + typeAttr + '>\n' +
               renderValue(value, indent + '  ') +
               indent + '</claim>\n';
    }
    if (t === 'null') {
        return indent + '<claim name="' + xmlEscape(name) + '" type="null"/>\n';
    }
    return indent + '<claim name="' + xmlEscape(name) + '"' + typeAttr + '>' +
           xmlEscape(value) + '</claim>\n';
}

function buildClaimsXml(header, claims) {
    var xml = '<claims status="valid"' +
              ' kid="' + xmlEscape(header.kid || '') + '"' +
              ' alg="' + xmlEscape(header.alg || '') + '">\n';
    Object.keys(claims).forEach(function (name) {
        xml += renderClaim(name, claims[name], '  ');
    });
    xml += '</claims>';
    return xml;
}

function buildErrorXml(code, message, detail) {
    var xml = '<error status="invalid">\n' +
              '  <code>' + xmlEscape(code) + '</code>\n' +
              '  <message>' + xmlEscape(message) + '</message>\n';
    if (CONFIG.includeErrorDetail && detail) {
        xml += '  <detail>' + xmlEscape(detail) + '</detail>\n';
    }
    xml += '  <timestamp>' + new Date().toISOString() + '</timestamp>\n' +
           '</error>';
    return xml;
}

/* ========================== OUTPUT HANDLING ============================ */

var finished = false;   // guarantee exactly one write to the output context

function writeXml(xml) {
    hm.current.set('Content-Type', 'application/xml');
    session.output.write(xml);
}

function succeed(header, claims) {
    if (finished) { return; }
    finished = true;

    sm.setVar('var://context/jwt/valid',  'true');
    sm.setVar('var://context/jwt/claims', JSON.stringify(claims));
    sm.setVar('var://context/jwt/sub',    claims.sub || '');

    console.info('[entra-jwt] token valid for sub=' + claims.sub + ' aud=' + claims.aud);
    writeXml(buildClaimsXml(header, claims));
}

function fail(code, message, detail) {
    if (finished) { return; }
    finished = true;

    console.error('[entra-jwt] ' + code + ': ' + message + (detail ? ' :: ' + detail : ''));
    sm.setVar('var://context/jwt/valid',      'false');
    sm.setVar('var://context/jwt/error-code', code);

    writeXml(buildErrorXml(code, message, detail));

    if (CONFIG.rejectOnFailure) {
        sm.setVar('var://service/error-protocol-response', '401');
        sm.setVar('var://service/error-protocol-reason-phrase', 'Unauthorized');
        session.reject('Unauthorized: ' + message);
    }
}

/* ============================== JWT HELPERS ============================ */

function b64urlDecode(str) {
    var s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    return Buffer.from(s, 'base64').toString('utf8');
}

function getBearerToken() {
    var auth = hm.current.get('Authorization');
    if (!auth) { return { error: 'MISSING_TOKEN' }; }
    var m = /^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\s*$/i.exec(auth);
    return m ? { token: m[1] } : { error: 'MALFORMED_AUTH_HEADER' };
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

    try {
        urlopen.open(options, function (err, response) {
            if (err) {
                return callback('JWKS fetch error: ' + (err.errorMessage || String(err)));
            }
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
    } catch (e) {
        callback('JWKS fetch exception: ' + e);
    }
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

// callback(errCode, errDetail, jwk)
function getKeyForKid(kid, callback) {
    fetchJwks(false, function (err, jwks) {
        if (err) { return callback('JWKS_UNAVAILABLE', err); }
        var key = findKey(jwks, kid);
        if (key) { return callback(null, null, key); }

        // kid not found: possible signing-key rollover and stale cache -> refetch once
        console.warn('[entra-jwt] kid ' + kid + ' not in cached JWKS, refetching');
        fetchJwks(true, function (err2, freshJwks) {
            if (err2) { return callback('JWKS_UNAVAILABLE', err2); }
            var freshKey = findKey(freshJwks, kid);
            if (!freshKey) { return callback('KEY_NOT_FOUND', 'No JWKS key matches kid ' + kid); }
            callback(null, null, freshKey);
        });
    });
}

function verifySignature(token, jwk, callback) {
    var jwsObj, verifier;
    try {
        jwsObj = jose.parse(token);
        jwsObj.getSignatures().forEach(function (sig) { sig.setKey(jwk); });
        verifier = jose.createJWSVerifier(jwsObj);
    } catch (e) {
        return callback('Unable to prepare JWS verification: ' + e);
    }
    verifier.validate(function (err) {
        if (err) { return callback('Signature verification failed: ' + err); }
        callback(null);
    });
}

// returns null when valid, otherwise { code, message }
function validateClaims(claims) {
    var now  = Math.floor(Date.now() / 1000);
    var skew = CONFIG.clockSkewSec;

    if (typeof claims.exp !== 'number') {
        return { code: 'MISSING_EXP', message: 'Missing exp claim' };
    }
    if (now > claims.exp + skew) {
        return { code: 'TOKEN_EXPIRED', message: 'Token expired' };
    }
    if (typeof claims.nbf === 'number' && now + skew < claims.nbf) {
        return { code: 'TOKEN_NOT_YET_VALID', message: 'Token not yet valid' };
    }
    if (typeof claims.iat === 'number' && claims.iat > now + skew) {
        return { code: 'INVALID_IAT', message: 'Token issued in the future' };
    }
    if (CONFIG.issuers.indexOf(claims.iss) === -1) {
        return { code: 'INVALID_ISSUER', message: 'Invalid issuer: ' + claims.iss };
    }
    if (claims.tid && claims.tid !== CONFIG.tenantId) {
        return { code: 'INVALID_TENANT', message: 'Invalid tenant: ' + claims.tid };
    }

    var aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    var audOk = aud.some(function (a) { return CONFIG.audiences.indexOf(a) !== -1; });
    if (!audOk) {
        return { code: 'INVALID_AUDIENCE', message: 'Invalid audience: ' + aud.join(',') };
    }

    if (CONFIG.requiredScopes.length) {
        var scopes = (claims.scp || '').split(' ');
        var missingScope = CONFIG.requiredScopes.filter(function (s) {
            return scopes.indexOf(s) === -1;
        });
        if (missingScope.length) {
            return { code: 'INSUFFICIENT_SCOPE',
                     message: 'Missing scope(s): ' + missingScope.join(',') };
        }
    }
    if (CONFIG.requiredRoles.length) {
        var roles = claims.roles || [];
        var missingRole = CONFIG.requiredRoles.filter(function (r) {
            return roles.indexOf(r) === -1;
        });
        if (missingRole.length) {
            return { code: 'INSUFFICIENT_ROLE',
                     message: 'Missing role(s): ' + missingRole.join(',') };
        }
    }
    return null;
}

/* ================================ MAIN ================================= */

(function main() {
    try {
        var bearer = getBearerToken();
        if (bearer.error === 'MISSING_TOKEN') {
            return fail('MISSING_TOKEN', 'Authorization header with Bearer token is required');
        }
        if (bearer.error) {
            return fail('MALFORMED_AUTH_HEADER', 'Authorization header is not a valid Bearer JWT');
        }
        var token = bearer.token;

        var parts = token.split('.');
        var header, claims;
        try {
            header = JSON.parse(b64urlDecode(parts[0]));
            claims = JSON.parse(b64urlDecode(parts[1]));
        } catch (e) {
            return fail('MALFORMED_JWT', 'JWT header or payload is not valid JSON', String(e));
        }

        // Prevent alg confusion (none / HS256 with public key)
        if (header.alg !== 'RS256') {
            return fail('UNSUPPORTED_ALG', 'Unsupported signing algorithm', 'alg=' + header.alg);
        }
        if (!header.kid) {
            return fail('MISSING_KID', 'JWT header has no kid');
        }
        // Microsoft Graph tokens carry a "nonce" header and are NOT meant to be
        // validated by your API - they always fail signature verification.
        if (header.nonce) {
            return fail('WRONG_AUDIENCE_TOKEN', 'Token was not issued for this API',
                        'nonce header present (Microsoft Graph token?)');
        }

        getKeyForKid(header.kid, function (keyErrCode, keyErrDetail, jwk) {
            if (keyErrCode) {
                return fail(keyErrCode, 'Unable to obtain signing key', keyErrDetail);
            }
            verifySignature(token, jwk, function (sigErr) {
                if (sigErr) {
                    return fail('INVALID_SIGNATURE', 'Token signature is invalid', sigErr);
                }
                var claimErr = validateClaims(claims);
                if (claimErr) {
                    return fail(claimErr.code, claimErr.message);
                }
                succeed(header, claims);
            });
        });
    } catch (e) {
        fail('INTERNAL_ERROR', 'Unexpected error during token validation', String(e));
    }
})();

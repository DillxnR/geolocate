addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  
  if (url.pathname !== '/geo') {
    return new Response('not found', { status: 404 })
  }
  
  if (request.method !== 'GET') {
    return new Response('method not allowed', {
      status: 405,
      headers: { 'Allow': 'GET' }
    })
  }
  
  try {
    const clientIP = getClientIP(request)
    const queryIP = url.searchParams.get('ip')
    const targetIP = queryIP || clientIP
    
    if (!isValidIP(targetIP)) {
      return createErrorResponse('invalid IP address format', 400)
    }
    
    if (isPrivateIP(targetIP)) {
      return createErrorResponse('cannot geolocate private IP addresses', 400)
    }
    
    const cacheKey = `geo:${targetIP}`
    const cache = caches.default
    let response = await cache.match(cacheKey)
    
    if (!response) {
      const geoData = await getGeolocationData(request, targetIP, queryIP !== null)
      response = new Response(JSON.stringify(geoData), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=21600',
          ...getCORSHeaders()
        }
      })
      
      event.waitUntil(cache.put(cacheKey, response.clone()))
    } else {
      const headers = new Headers(response.headers)
      Object.assign(headers, getCORSHeaders())
      response = new Response(response.body, { headers })
    }
    
    return response
    
  } catch (error) {
    console.error('geolocation error:', error)
    return createErrorResponse('internal server error', 500)
  }
}

function getClientIP(request) {
  const cfConnectingIP = request.headers.get('CF-Connecting-IP')
  if (cfConnectingIP) return cfConnectingIP
  
  const xForwardedFor = request.headers.get('X-Forwarded-For')
  if (xForwardedFor) {
    return xForwardedFor.split(',')[0].trim()
  }
  
  const xRealIP = request.headers.get('X-Real-IP')
  if (xRealIP) return xRealIP
  
  return request.headers.get('CF-Connecting-IP') || '127.0.0.1'
}

function isValidIP(ip) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip)
}

function isPrivateIP(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
    return true
  }
  
  const ipv4PrivateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./
  ]
  
  return ipv4PrivateRanges.some(range => range.test(ip))
}

async function getGeolocationData(request, targetIP, isQueryIP) {
  const cf = request.cf || {}
  
  if (isQueryIP) {
    return {
      ip: targetIP,
      country: 'Unknown',
      countryCode: 'XX',
      region: 'Unknown',
      city: 'Unknown',
      timezone: 'Unknown',
      note: 'geolocation data only available for the requesting client IP'
    }
  }
  
  return {
    ip: targetIP,
    country: cf.country || 'Unknown',
    countryCode: cf.colo ? cf.country : 'XX',
    region: cf.region || cf.regionCode || 'Unknown',
    city: cf.city || 'Unknown',
    timezone: cf.timezone || 'Unknown',
    asn: cf.asn || null,
    asOrganization: cf.asOrganization || null
  }
}

function getCORSHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400'
  }
}

function createErrorResponse(message, status) {
  return new Response(JSON.stringify({ 
    error: message,
    status: status 
  }), {
    status: status,
    headers: {
      'Content-Type': 'application/json',
      ...getCORSHeaders()
    }
  })
}
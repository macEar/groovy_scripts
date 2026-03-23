import javax.net.ssl.*
import java.security.cert.X509Certificate
import java.io.OutputStream
import java.io.InputStream

final TrustManager[] trustAllCerts = [
    new X509TrustManager() {
        X509Certificate[] getAcceptedIssuers() { return null }
        void checkClientTrusted(X509Certificate[] certs, String authType) {}
        void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
] as TrustManager[]

SSLContext sc = SSLContext.getInstance("TLS")
sc.init(null, trustAllCerts, new java.security.SecureRandom())

HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

HostnameVerifier allHostsValid = new HostnameVerifier() {
    boolean verify(String hostname, SSLSession session) {
        return true
    }
}
HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid)

def targetUrl = PAYLOAD?.get("url")?.asText()
def filePath = PAYLOAD?.get("file")?.asText()

if (!targetUrl || !filePath) {
    throw new Exception("URL или путь к файлу не указаны в PAYLOAD")
}

def file = new File(filePath)
if (!file.exists() || !file.isFile()) {
    throw new Exception("Файл не найден или не является файлом: ${filePath}")
}

def url = new URL(targetUrl)
def conn = (HttpURLConnection) url.openConnection()

try {
    conn.setRequestMethod("POST")
    conn.setDoOutput(true)
    conn.setConnectTimeout(10000)
    conn.setReadTimeout(30000)

    conn.setRequestProperty("Content-Type", "application/octet-stream")
    conn.setRequestProperty("Accept", "application/json")
    
    if (USER_AUTHORITIES) {
        conn.setRequestProperty("X-User-Authorities", USER_AUTHORITIES.toString())
    }
    if (USER_PARTNER_ID) {
        conn.setRequestProperty("X-Partner-ID", USER_PARTNER_ID.toString())
    }
    if (COMPANY_SERVICE) {
        conn.setRequestProperty("X-Company-Service", COMPANY_SERVICE.toString())
    }

    byte[] fileBytes = file.bytes

    OutputStream os = conn.getOutputStream()
    try {
        os.write(fileBytes)
        os.flush()
    } finally {
        os.close()
    }

    int responseCode = conn.getResponseCode()

    InputStream inputStream = (responseCode >= 200 && responseCode < 300) 
        ? conn.getInputStream() 
        : conn.getErrorStream()

    String responseBody = inputStream?.text ?: ""

    if (responseCode >= 400) {
        throw new Exception("HTTP Error ${responseCode}: ${responseBody}")
    }

} finally {
    conn.disconnect()
}

return [
    ok: true
]

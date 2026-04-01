package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateList
import at.asitplus.signum.indispensable.pki.OCSPRequest
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.buffered
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray
import kotlinx.serialization.json.Json

interface OcspProvider {

    suspend fun fetchOcspResponse(ocspUrl: String, request: OCSPRequest): ByteArray

}

class HttpOCSPProvider : OcspProvider {

    private val httpClient = HttpClient {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }
    }

    override suspend fun fetchOcspResponse(ocspUrl: String, request: OCSPRequest): ByteArray {
        val requestBytes = request.encodeToTlv().derEncoded

        val response = httpClient.post(ocspUrl) {
            contentType(ContentType.parse("application/ocsp-request"))
            setBody(requestBytes)
            header(HttpHeaders.Accept, "application/ocsp-response")
        }

        if (response.status != HttpStatusCode.OK) {
            throw CertificateException("OCSP responder returned status ${response.status}")
        }

        return response.body()
    }

}

@ExperimentalPkiApi
object SystemOcspCache {
    private val mutex = Mutex()
    private var _cache: Map<String, ByteArray>? = null

    /**
     * Provides the cache. Throws if accessed before [initialize] is called.
     */
    val responses: Map<String, ByteArray>
        get() = _cache ?: throw IllegalStateException("SystemOcspCache not initialized. Call initialize() first.")

    /**
     * Suspendable initializer. Safe to call multiple times; only the first succeeds.
     */
    suspend fun initialize(path: String, fileSystem: FileSystem = SystemFileSystem) {
        if (_cache != null) return
        mutex.withLock {
            if (_cache == null) {
                val provider = DirectoryOcspProvider.create(path, fileSystem)
                _cache = provider.ocspCache
            }
        }
    }
}

class DirectoryOcspProvider @OptIn(ExperimentalPkiApi::class) constructor(
    val ocspCache: Map<String, ByteArray> = SystemOcspCache.responses
) : OcspProvider {

    override suspend fun fetchOcspResponse(ocspUrl: String, request: OCSPRequest): ByteArray {
        // Extract the last path segment from the URL
        val fileName = ocspUrl.substringAfterLast('/')

        return ocspCache[fileName]
            ?: throw CertificateException("OCSP response not found in cache for URL: $ocspUrl (expected file: $fileName.ocsp)")
    }

    companion object {
        suspend fun create(
            folderPath: String,
            fileSystem: FileSystem = SystemFileSystem
        ): DirectoryOcspProvider = withContext(Dispatchers.Default) {
            val cache = mutableMapOf<String, ByteArray>()
            val rootPath = Path(folderPath)

            if (!fileSystem.exists(rootPath)) {
                return@withContext DirectoryOcspProvider(emptyMap())
            }

            fileSystem.list(rootPath).forEach { filePath ->
                if (filePath.name.endsWith(".ocsp", ignoreCase = true)) {
                    runCatching {
                        val bytes = fileSystem.source(filePath).buffered().use { it.readByteArray() }
                        val key = filePath.name.removeSuffix(".ocsp")
                        cache[key] = bytes
                    }.onFailure {
                        println("Failed to load OCSP response at ${filePath.name}: ${it.message}")
                    }
                }
            }
            DirectoryOcspProvider(cache)
        }
    }
}
package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateException
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.OCSPResponseException
import at.asitplus.signum.indispensable.pki.OCSPRequest
import at.asitplus.signum.supreme.validate.SystemOcspCache.initialize
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
import kotlinx.coroutines.withContext
import kotlinx.io.buffered
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray
import kotlinx.serialization.json.Json

/**
 * Provides OCSP responses for certificate validation
 * The returned response is expected to be the raw DER-encoded OCSP response bytes
 * as defined in RFC 6960.
 */
interface OCSPProvider {

    suspend fun fetchOcspResponse(ocspUrl: String, request: OCSPRequest): ByteArray

}

/**
 * Basic HTTP based implementation
 */
class HttpOCSPProvider : OCSPProvider {

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
            throw OCSPResponseException("OCSP responder returned status ${response.status}")
        }

        return response.body()
    }

}

/**
 * Global cache of OCSP responses
 */
@ExperimentalPkiApi
object SystemOcspCache {
    private var _cache: Map<String, ByteArray>? = null

    /**
     * Provides the cache. Throws if accessed before [initialize] is called.
     */
    val responses: Map<String, ByteArray>
        get() = _cache ?: throw IllegalStateException("SystemOcspCache not initialized. Call initialize() first.")

    suspend fun initialize(path: String, fileSystem: FileSystem = SystemFileSystem) {
        if (_cache == null) {
            val provider = DirectoryOcspProvider.create(path, fileSystem)
            _cache = provider.ocspCache
        }
    }
}

/**
 * File system–based implementation of [OCSPProvider].
 *
 * This provider serves OCSP responses from a preloaded in-memory cache
 */
class DirectoryOcspProvider @OptIn(ExperimentalPkiApi::class) constructor(
    val ocspCache: Map<String, ByteArray> = SystemOcspCache.responses
) : OCSPProvider {

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
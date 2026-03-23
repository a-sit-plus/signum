package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.CertificateList
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLDistributionPointsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.IssuingDistributionPointExtension
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.buffered
import kotlinx.io.files.FileSystem
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray

/**
 * Fetches Certificate Revocation Lists
 */
interface CrlProvider {
    /**
     * Attempts to find a valid CRL for the given issuer.
     */
    suspend fun getCrl(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList>

    /**
     * Fetch CRLs from CRL Distribution Points (CDP extension).
     */
    suspend fun getCrlsFromDistributionPoints(cert: X509Certificate): List<CertificateList>
}


@ExperimentalPkiApi
object SystemCrlCache {
    private val mutex = Mutex()
    private var _cache: List<CertificateList>? = null

    /**
     * Provides the cache. Throws if accessed before [initialize] is called.
     */
    val crls: List<CertificateList>
        get() = _cache ?: throw IllegalStateException("SystemCrlCache not initialized. Call initialize() first.")

    /**
     * Suspendable initializer. Safe to call multiple times; only the first succeeds.
     */
    suspend fun initialize(path: String, fileSystem: FileSystem = SystemFileSystem) {
        if (_cache != null) return
        mutex.withLock {
            if (_cache == null) {
                val provider = DirectoryCrlProvider.create(path, fileSystem)
                _cache = provider.crlCache
            }
        }
    }
}

/**
 * A provider that loads and caches all CRLs from a specific local directory.
 * * It scans the directory for files ending in ".crl" (or another specified extension),
 * parses them, and holds them in memory for lightning-fast lookups during validation.
 */
class DirectoryCrlProvider @OptIn(ExperimentalPkiApi::class) constructor(
    val crlCache: List<CertificateList> = SystemCrlCache.crls
) : CrlProvider {

    /**
     * Finds the CRL issued by the [issuerCert].
     */
    @OptIn(ExperimentalPkiApi::class)
    override suspend fun getCrl(targetCert: X509Certificate, issuerCert: X509Certificate): List<CertificateList> {
        val issuerName = issuerCert.tbsCertificate.subjectName

        return crlCache.filter { crl ->
                crl.tbsCertList.issuer.constrains(issuerName) == GeneralNameOption.ConstraintResult.MATCH
            }
    }

    companion object {
        suspend fun create(
            folderPath: String,
            fileSystem: FileSystem = SystemFileSystem
        ): DirectoryCrlProvider = withContext(Dispatchers.Default) {
            val cache = mutableListOf<CertificateList>()
            val rootPath = Path(folderPath)

            if (!fileSystem.exists(rootPath)) {
                return@withContext DirectoryCrlProvider(emptyList())
            }

            fileSystem.list(rootPath).forEach { filePath ->
                if (filePath.name.endsWith(".crl", ignoreCase = true)) {
                    runCatching {
                        val bytes = fileSystem.source(filePath).buffered().use {
                            it.readByteArray()
                        }

                        val src = Asn1Element.parse(bytes) as Asn1Sequence
                        val crl = CertificateList.decodeFromTlv(src)

                        cache.add(crl)
                    }.onFailure {
                        println("Failed to load CRL at ${filePath.name}: ${it.message}")
                    }
                }
            }
            DirectoryCrlProvider(cache)
        }
    }

    override suspend fun getCrlsFromDistributionPoints(
        cert: X509Certificate
    ): List<CertificateList> {

        val result = mutableListOf<CertificateList>()

        val cdpExt = cert.findExtension<CRLDistributionPointsExtension>()
            ?: return emptyList()

        for (dp in cdpExt.distributionPoints) {

            val dpName = dp.distributionPointName

            for (crl in crlCache) {

                if (dp.crlIssuer != null) {
                    val expectedIssuer = dp.crlIssuer!!.name
                    if (crl.tbsCertList.issuer == expectedIssuer) {
                        result.add(crl)
                    }
                    continue
                }

                if (crl.tbsCertList.issuer != cert.tbsCertificate.issuerName) {
                    continue
                }

                if (dpName != null) {
                    val idp = crl.findExtension<IssuingDistributionPointExtension>()
                    val idpName = idp?.distributionPointName

                    if (idpName != null) {
                        if (matchesDistributionPointNames(idpName,dpName, crl)) {
                            result.add(crl)
                        }
                    } else {
                        result.add(crl)
                    }
                } else {
                    result.add(crl)
                }
            }
        }

        return result.distinct()
    }
}